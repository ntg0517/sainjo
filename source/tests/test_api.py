"""인증 API 1단계 시험.

- 기본 실행(DB 없이): users 저장소를 메모리 가짜 객체로 바꿔 규약(CSRF, 401/403, 입력 검증, 오류 형식)을 검사합니다.
- MySQL 실행: CHAGEUN_MYSQL_DATABASE 등 시험 DB 환경변수를 설정했을 때만 실제 저장·재로그인을 검사합니다.
  반드시 시험 DB를 지정하세요. 실제 사용자 DB를 가리키면 안 됩니다.

실행(source 폴더에서):
    .\\.venv\\Scripts\\python.exe -m unittest discover -s tests -p "test_api*.py"
"""

import os
import secrets
import unittest
from unittest import mock

import pymysql

from chageun import create_app

TEST_SECRET = "unit-test-secret-only-not-for-deploy"


class FakeUsers:
    """users 테이블을 흉내 내는 메모리 저장소. 중복 아이디는 MySQL과 같은 1062 오류를 냅니다."""

    def __init__(self):
        self.rows = {}
        self.next_id = 1

    def create(self, username, password_hash):
        if username in self.rows:
            raise pymysql.err.IntegrityError(1062, "Duplicate entry for key 'uq_users_username'")
        user_id = self.next_id
        self.next_id += 1
        self.rows[username] = {"id": user_id, "username": username, "password_hash": password_hash}
        return user_id

    def by_username(self, username):
        return self.rows.get(username)

    def by_id(self, user_id):
        for row in self.rows.values():
            if row["id"] == user_id:
                return {"id": row["id"], "username": row["username"]}
        return None


class FakeVehicles:
    """vehicles 테이블을 흉내 냅니다. owner_id UNIQUE 제약이 있어서 두 번째 차량은 MySQL과 같은 1062 오류를 냅니다."""

    def __init__(self):
        self.rows = {}
        self.next_id = 1

    def create(self, owner_id, fields):
        if any(row["owner_id"] == owner_id for row in self.rows.values()):
            raise pymysql.err.IntegrityError(1062, "Duplicate entry for key 'uq_vehicles_owner'")
        vehicle_id = self.next_id
        self.next_id += 1
        self.rows[vehicle_id] = {"id": vehicle_id, "owner_id": owner_id, **fields}
        return vehicle_id

    def list_by_owner(self, owner_id):
        return [dict(row) for row in self.rows.values() if row["owner_id"] == owner_id]

    def find_for_owner(self, vehicle_id, owner_id):
        row = self.rows.get(vehicle_id)
        if row is None or row["owner_id"] != owner_id:
            return None
        return dict(row)


class AuthApiTest(unittest.TestCase):
    def setUp(self):
        self.fake = FakeUsers()
        self.db = mock.MagicMock()
        self.create_mock = mock.patch(
            "chageun.api.users.create_user", side_effect=self.fake.create
        ).start()
        self.addCleanup(mock.patch.stopall)
        mock.patch("chageun.api.get_db", return_value=self.db).start()
        mock.patch(
            "chageun.api.users.find_user_by_username", side_effect=self.fake.by_username
        ).start()
        mock.patch("chageun.api.users.find_user_by_id", side_effect=self.fake.by_id).start()

        app = create_app({"TESTING": True, "CHAGEUN_SERVER_MODE": True, "SECRET_KEY": TEST_SECRET})
        self.client = app.test_client()

    def csrf(self):
        response = self.client.get("/api/auth/csrf")
        self.assertEqual(response.status_code, 200)
        return response.get_json()["data"]["csrf_token"]

    def post(self, path, body=None, token=None):
        headers = {} if token is None else {"X-CSRF-Token": token}
        return self.client.post(path, json=body, headers=headers)

    def register(self, username="tester_a", password="correct-horse"):
        return self.post(
            "/api/auth/register", {"username": username, "password": password}, self.csrf()
        )

    def login(self, username="tester_a", password="correct-horse"):
        return self.post("/api/auth/login", {"username": username, "password": password}, self.csrf())

    def assert_error(self, response, status, code):
        self.assertEqual(response.status_code, status)
        body = response.get_json()
        self.assertEqual(body["error"]["code"], code)
        self.assertIsInstance(body["error"]["fields"], dict)
        self.assertEqual(body["meta"]["contract_version"], "1.0")
        return body

    def test_csrf_endpoint_returns_token_in_envelope(self):
        response = self.client.get("/api/auth/csrf")
        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(body["data"]["csrf_token"])
        self.assertEqual(body["meta"]["contract_version"], "1.0")
        self.assertEqual(body["meta"]["mode"], "live")
        self.assertEqual(body["meta"]["calculation_mode"], "none")

    def test_register_without_csrf_is_403(self):
        response = self.post("/api/auth/register", {"username": "tester_a", "password": "correct-horse"})
        self.assert_error(response, 403, "CSRF_FAILED")
        self.assertEqual(self.fake.rows, {})

    def test_register_with_wrong_or_non_ascii_csrf_is_403_not_500(self):
        self.csrf()
        for token in ["wrong-token", "한글토큰"]:
            response = self.post(
                "/api/auth/register", {"username": "tester_a", "password": "correct-horse"}, token
            )
            self.assert_error(response, 403, "CSRF_FAILED")

    def test_register_success_returns_201_without_secrets_and_no_auto_login(self):
        response = self.register()
        self.assertEqual(response.status_code, 201)
        data = response.get_json()["data"]
        self.assertEqual(data, {"id": 1, "username": "tester_a"})
        self.assertNotIn("password", response.get_data(as_text=True))
        self.assertNotIn("password_hash", response.get_data(as_text=True))
        # 가입만으로는 로그인되지 않습니다.
        self.assert_error(self.client.get("/api/auth/me"), 401, "AUTH_REQUIRED")
        # 저장된 값은 해시입니다.
        self.assertNotEqual(self.fake.rows["tester_a"]["password_hash"], "correct-horse")

    def test_register_duplicate_username_is_409(self):
        self.assertEqual(self.register().status_code, 201)
        response = self.register()
        body = self.assert_error(response, 409, "CONFLICT")
        self.assertIn("username", body["error"]["fields"])

    def test_register_rejects_invalid_username_and_password_with_field_errors(self):
        cases = [
            {"username": "Tester_A", "password": "correct-horse"},
            {"username": "ab", "password": "correct-horse"},
            {"username": "tester_a\n", "password": "correct-horse"},
            {"username": "tester_a", "password": "short"},
            {"username": "tester_a", "password": "x" * 129},
            {"username": "tester_a", "password": "correct-horse", "role": "admin"},
        ]
        for body in cases:
            with self.subTest(body=body):
                response = self.post("/api/auth/register", body, self.csrf())
                error = self.assert_error(response, 400, "VALIDATION_ERROR")
                self.assertTrue(error["error"]["fields"])
        self.assertEqual(self.fake.rows, {})

    def test_password_is_not_trimmed(self):
        response = self.register(password="  spaced-pass  ")
        self.assertEqual(response.status_code, 201)
        self.assert_error(self.login(password="spaced-pass"), 401, "INVALID_CREDENTIALS")
        self.assertEqual(self.login(password="  spaced-pass  ").status_code, 200)

    def test_non_object_json_is_400(self):
        response = self.post("/api/auth/register", ["tester_a", "correct-horse"], self.csrf())
        self.assert_error(response, 400, "VALIDATION_ERROR")

    def test_wrong_password_and_unknown_user_return_same_error(self):
        self.register()
        wrong_password = self.login(password="wrong-password-1")
        unknown_user = self.login(username="nobody_here")
        self.assert_error(wrong_password, 401, "INVALID_CREDENTIALS")
        self.assert_error(unknown_user, 401, "INVALID_CREDENTIALS")
        self.assertEqual(wrong_password.get_json()["error"]["message"], unknown_user.get_json()["error"]["message"])

    def test_login_me_logout_flow_and_token_regenerated(self):
        self.register()
        old_token = self.csrf()
        response = self.post("/api/auth/login", {"username": "tester_a", "password": "correct-horse"}, old_token)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["data"], {"id": 1, "username": "tester_a"})

        me = self.client.get("/api/auth/me")
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.get_json()["data"], {"id": 1, "username": "tester_a"})

        # 로그인 후 이전 CSRF 토큰은 더 이상 유효하지 않습니다.
        self.assert_error(self.post("/api/auth/logout", None, old_token), 403, "CSRF_FAILED")

        new_token = self.csrf()
        self.assertNotEqual(new_token, old_token)
        logout = self.post("/api/auth/logout", None, new_token)
        self.assertEqual(logout.status_code, 200)
        self.assertEqual(logout.get_json()["data"], {"logged_out": True})
        self.assert_error(self.client.get("/api/auth/me"), 401, "AUTH_REQUIRED")

    def test_me_without_login_is_401(self):
        self.assert_error(self.client.get("/api/auth/me"), 401, "AUTH_REQUIRED")

    def test_logout_without_login_is_401_even_without_csrf(self):
        self.assert_error(self.post("/api/auth/logout"), 401, "AUTH_REQUIRED")

    def test_logout_when_logged_in_without_csrf_is_403(self):
        self.register()
        self.login()
        self.assert_error(self.post("/api/auth/logout"), 403, "CSRF_FAILED")
        self.assertEqual(self.client.get("/api/auth/me").status_code, 200)

    def test_database_error_is_500_and_hides_details(self):
        self.create_mock.side_effect = pymysql.err.OperationalError(
            2003, "Can't connect to MySQL server password=super-secret-value"
        )
        response = self.register()
        self.assert_error(response, 500, "INTERNAL_ERROR")
        text = response.get_data(as_text=True)
        self.assertNotIn("super-secret-value", text)
        self.assertNotIn("MySQL", text)
        self.db.rollback.assert_called()

    def test_unknown_api_route_is_404(self):
        response = self.client.post("/api/auth/does-not-exist", json={}, headers={"X-CSRF-Token": self.csrf()})
        self.assertEqual(response.status_code, 404)


@unittest.skipUnless(
    os.environ.get("CHAGEUN_TEST_MYSQL_DATABASE"),
    "시험 MySQL 환경변수(CHAGEUN_TEST_MYSQL_DATABASE 등)가 없어 실제 DB 시험을 건너뜁니다.",
)
class MySqlAuthPersistenceTest(unittest.TestCase):
    """실제 MySQL에서 가입 → 재로그인 → 조회가 유지되는지 확인합니다. 시험 DB에서만 실행하세요."""

    def setUp(self):
        self.app = create_app({"TESTING": True, "CHAGEUN_SERVER_MODE": True, "SECRET_KEY": TEST_SECRET})
        self.client = self.app.test_client()
        self.username = f"tester_{secrets.token_hex(4)}"
        self.password = "correct-horse-battery"

    def tearDown(self):
        config = self.app.config
        conn = pymysql.connect(
            host=config["MYSQL_HOST"],
            port=config["MYSQL_PORT"],
            user=config["MYSQL_USER"],
            password=config["MYSQL_PASSWORD"],
            database=config["MYSQL_DATABASE"],
            charset="utf8mb4",
        )
        try:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM users WHERE username = %s", (self.username,))
            conn.commit()
        finally:
            conn.close()

    def csrf(self):
        return self.client.get("/api/auth/csrf").get_json()["data"]["csrf_token"]

    def test_register_login_me_persist_across_new_client(self):
        token = self.csrf()
        register = self.client.post(
            "/api/auth/register",
            json={"username": self.username, "password": self.password},
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(register.status_code, 201)

        # 새 클라이언트(= 재로그인에 해당)에서 다시 로그인합니다.
        other = self.app.test_client()
        token = other.get("/api/auth/csrf").get_json()["data"]["csrf_token"]
        login = other.post(
            "/api/auth/login",
            json={"username": self.username, "password": self.password},
            headers={"X-CSRF-Token": token},
        )
        self.assertEqual(login.status_code, 200)
        me = other.get("/api/auth/me")
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.get_json()["data"]["username"], self.username)


class VehicleApiTest(unittest.TestCase):
    """차량 등록·조회 API. 저장소는 메모리 가짜 객체로 바꿔 규약을 검사합니다."""

    VALID = {
        "manufacturer": "현대",
        "model": "그랜저",
        "generation": "DL3",
        "year": 2020,
        "engine": "2.5 가솔린",
        "fuel": "가솔린",
        "transmission": "자동",
        "mileage": 0,
        "reference_date": "2026-03-01",
        "conditions": "normal",
    }

    def setUp(self):
        self.users = FakeUsers()
        self.vehicles = FakeVehicles()
        self.db = mock.MagicMock()
        mock.patch("chageun.api.users.create_user", side_effect=self.users.create).start()
        mock.patch("chageun.api.users.find_user_by_username", side_effect=self.users.by_username).start()
        mock.patch("chageun.api.users.find_user_by_id", side_effect=self.users.by_id).start()
        mock.patch("chageun.api.vehicles.create_vehicle", side_effect=self.vehicles.create).start()
        mock.patch(
            "chageun.api.vehicles.list_vehicles_by_owner", side_effect=self.vehicles.list_by_owner
        ).start()
        mock.patch(
            "chageun.api.vehicles.find_vehicle_for_owner", side_effect=self.vehicles.find_for_owner
        ).start()
        mock.patch("chageun.api.get_db", return_value=self.db).start()
        self.addCleanup(mock.patch.stopall)
        self.app = create_app({"TESTING": True, "CHAGEUN_SERVER_MODE": True, "SECRET_KEY": TEST_SECRET})

    def csrf(self, client):
        return client.get("/api/auth/csrf").get_json()["data"]["csrf_token"]

    def register_and_login(self, username):
        """계정을 만들고 로그인된 클라이언트를 돌려줍니다. 계정마다 별도 클라이언트를 씁니다."""
        client = self.app.test_client()
        password = "correct-horse"
        client.post(
            "/api/auth/register",
            json={"username": username, "password": password},
            headers={"X-CSRF-Token": self.csrf(client)},
        )
        response = client.post(
            "/api/auth/login",
            json={"username": username, "password": password},
            headers={"X-CSRF-Token": self.csrf(client)},
        )
        self.assertEqual(response.status_code, 200)
        return client

    def create(self, client, body=None):
        return client.post(
            "/api/vehicles",
            json=self.VALID if body is None else body,
            headers={"X-CSRF-Token": self.csrf(client)},
        )

    def assert_error(self, response, status, code):
        self.assertEqual(response.status_code, status)
        body = response.get_json()
        self.assertEqual(body["error"]["code"], code)
        self.assertIsInstance(body["error"]["fields"], dict)
        self.assertEqual(body["meta"]["contract_version"], "1.0")
        return body

    def test_list_without_login_is_401(self):
        self.assert_error(self.app.test_client().get("/api/vehicles"), 401, "AUTH_REQUIRED")

    def test_create_without_login_is_401_even_without_csrf(self):
        client = self.app.test_client()
        self.assert_error(client.post("/api/vehicles", json=self.VALID), 401, "AUTH_REQUIRED")
        self.assertEqual(self.vehicles.rows, {})

    def test_create_without_csrf_is_403(self):
        client = self.register_and_login("owner_a")
        self.assert_error(client.post("/api/vehicles", json=self.VALID), 403, "CSRF_FAILED")
        self.assertEqual(self.vehicles.rows, {})

    def test_create_returns_201_and_reads_back_saved_values(self):
        client = self.register_and_login("owner_a")
        response = self.create(client)
        self.assertEqual(response.status_code, 201)
        data = response.get_json()["data"]
        self.assertEqual(data["manufacturer"], "현대")
        self.assertEqual(data["model"], "그랜저")
        self.assertEqual(data["generation"], "DL3")
        self.assertEqual(data["year"], 2020)
        self.assertEqual(data["mileage"], 0)
        self.assertEqual(data["reference_date"], "2026-03-01")
        self.assertEqual(data["conditions"], "normal")
        self.assertNotIn("owner_id", data)
        self.assertNotIn("owner_id", response.get_data(as_text=True))

    def test_mileage_zero_and_null_are_kept_apart(self):
        zero_owner = self.register_and_login("owner_a")
        null_owner = self.register_and_login("owner_b")
        self.create(zero_owner, {**self.VALID, "mileage": 0, "reference_date": None})
        self.create(null_owner, {**self.VALID, "mileage": None, "reference_date": "2026-03-01"})

        zero = zero_owner.get("/api/vehicles").get_json()["data"][0]
        null = null_owner.get("/api/vehicles").get_json()["data"][0]
        self.assertEqual(zero["mileage"], 0)
        self.assertIsNone(zero["reference_date"])
        self.assertIsNone(null["mileage"])
        self.assertEqual(null["reference_date"], "2026-03-01")

    def test_defaults_when_optional_fields_are_missing(self):
        client = self.register_and_login("owner_a")
        response = self.create(client, {"manufacturer": "현대", "model": "그랜저"})
        self.assertEqual(response.status_code, 201)
        data = response.get_json()["data"]
        self.assertEqual(data["conditions"], "unknown")
        self.assertIsNone(data["mileage"])
        self.assertIsNone(data["year"])
        self.assertIsNone(data["reference_date"])

    def test_second_vehicle_for_same_account_is_409(self):
        client = self.register_and_login("owner_a")
        self.assertEqual(self.create(client).status_code, 201)
        self.assert_error(self.create(client), 409, "CONFLICT")
        self.assertEqual(len(self.vehicles.rows), 1)

    def test_invalid_input_is_400_with_field_errors_and_nothing_saved(self):
        cases = [
            {k: v for k, v in self.VALID.items() if k != "manufacturer"},
            {**self.VALID, "model": "가" * 41},
            {**self.VALID, "manufacturer": "   "},
            {**self.VALID, "generation": "XX"},
            {**self.VALID, "year": 1899},
            {**self.VALID, "year": 2036},
            {**self.VALID, "year": "2020"},
            {**self.VALID, "year": True},
            {**self.VALID, "mileage": -1},
            {**self.VALID, "mileage": 1000001},
            {**self.VALID, "mileage": 1.5},
            {**self.VALID, "mileage": "100"},
            {**self.VALID, "mileage": True},
            {**self.VALID, "reference_date": "2026-02-30"},
            {**self.VALID, "reference_date": "2026/03/01"},
            {**self.VALID, "reference_date": "2026-1-1"},
            {**self.VALID, "reference_date": 20260301},
            {**self.VALID, "conditions": "bad"},
            {**self.VALID, "conditions": None},
            {**self.VALID, "owner_id": 999},
        ]
        client = self.register_and_login("owner_a")
        for body in cases:
            with self.subTest(body=body):
                error = self.assert_error(self.create(client, body), 400, "VALIDATION_ERROR")
                self.assertTrue(error["error"]["fields"])
        self.assertEqual(self.vehicles.rows, {})

    def test_list_shows_only_own_vehicle(self):
        owner_a = self.register_and_login("owner_a")
        owner_b = self.register_and_login("owner_b")
        self.assertEqual(self.create(owner_a).status_code, 201)
        self.assertEqual(owner_b.get("/api/vehicles").get_json()["data"], [])
        listed = owner_a.get("/api/vehicles").get_json()["data"]
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["model"], "그랜저")

    def test_detail_own_vehicle_is_200(self):
        owner_a = self.register_and_login("owner_a")
        vehicle_id = self.create(owner_a).get_json()["data"]["id"]
        response = owner_a.get(f"/api/vehicles/{vehicle_id}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["data"]["id"], vehicle_id)

    def test_detail_of_other_account_and_missing_vehicle_are_the_same_404(self):
        owner_a = self.register_and_login("owner_a")
        owner_b = self.register_and_login("owner_b")
        vehicle_id = self.create(owner_a).get_json()["data"]["id"]
        other = self.assert_error(owner_b.get(f"/api/vehicles/{vehicle_id}"), 404, "NOT_FOUND")
        missing = self.assert_error(owner_b.get("/api/vehicles/999"), 404, "NOT_FOUND")
        self.assertEqual(other["error"]["message"], missing["error"]["message"])

    def test_detail_without_login_is_401(self):
        self.assert_error(self.app.test_client().get("/api/vehicles/1"), 401, "AUTH_REQUIRED")

    def test_database_error_on_create_is_500_and_hides_details(self):
        client = self.register_and_login("owner_a")
        with mock.patch(
            "chageun.api.vehicles.create_vehicle",
            side_effect=pymysql.err.OperationalError(2013, "Lost connection password=super-secret-value"),
        ):
            response = self.create(client)
        self.assert_error(response, 500, "INTERNAL_ERROR")
        self.assertNotIn("super-secret-value", response.get_data(as_text=True))
        self.db.rollback.assert_called()


@unittest.skipUnless(
    os.environ.get("CHAGEUN_TEST_MYSQL_DATABASE"),
    "시험 MySQL 환경변수(CHAGEUN_TEST_MYSQL_DATABASE 등)가 없어 실제 DB 시험을 건너뜁니다.",
)
class MySqlVehiclePersistenceTest(unittest.TestCase):
    """실제 MySQL에 차량을 저장한 뒤 새 클라이언트에서 다시 조회합니다. 시험 DB에서만 실행하세요."""

    def setUp(self):
        self.app = create_app({"TESTING": True, "CHAGEUN_SERVER_MODE": True, "SECRET_KEY": TEST_SECRET})
        self.username = f"tester_{secrets.token_hex(4)}"
        self.password = "correct-horse-battery"

    def tearDown(self):
        # users 삭제 시 vehicles도 CASCADE로 함께 삭제됩니다.
        config = self.app.config
        conn = pymysql.connect(
            host=config["MYSQL_HOST"],
            port=config["MYSQL_PORT"],
            user=config["MYSQL_USER"],
            password=config["MYSQL_PASSWORD"],
            database=config["MYSQL_DATABASE"],
            charset="utf8mb4",
        )
        try:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM users WHERE username = %s", (self.username,))
            conn.commit()
        finally:
            conn.close()

    def csrf(self, client):
        return client.get("/api/auth/csrf").get_json()["data"]["csrf_token"]

    def test_saved_vehicle_is_read_back_by_new_client(self):
        client = self.app.test_client()
        client.post(
            "/api/auth/register",
            json={"username": self.username, "password": self.password},
            headers={"X-CSRF-Token": self.csrf(client)},
        )
        client.post(
            "/api/auth/login",
            json={"username": self.username, "password": self.password},
            headers={"X-CSRF-Token": self.csrf(client)},
        )
        created = client.post(
            "/api/vehicles",
            json={
                "manufacturer": "현대",
                "model": "그랜저",
                "generation": "DL3",
                "mileage": 0,
                "reference_date": None,
                "conditions": "normal",
            },
            headers={"X-CSRF-Token": self.csrf(client)},
        )
        self.assertEqual(created.status_code, 201)
        vehicle_id = created.get_json()["data"]["id"]

        # 새 클라이언트로 다시 로그인해서 조회합니다.
        other = self.app.test_client()
        other.post(
            "/api/auth/login",
            json={"username": self.username, "password": self.password},
            headers={"X-CSRF-Token": self.csrf(other)},
        )
        listed = other.get("/api/vehicles").get_json()["data"]
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["mileage"], 0)
        self.assertIsNone(listed[0]["reference_date"])

        detail = other.get(f"/api/vehicles/{vehicle_id}")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.get_json()["data"]["model"], "그랜저")


if __name__ == "__main__":
    unittest.main()
