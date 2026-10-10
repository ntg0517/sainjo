"""vehicles 테이블 접근. 커밋은 호출하는 API가 합니다. 모든 SQL은 파라미터 바인딩을 사용합니다.

모든 조회에 owner_id 조건을 함께 씁니다. 다른 계정의 차량은 None 또는 빈 목록으로만 돌아가므로
존재 여부가 드러나지 않습니다.
"""

from .db import get_db

# 아래 상수는 코드에 고정된 열 이름입니다. 사용자 입력은 열 이름으로 쓰지 않습니다.
WRITABLE_COLUMNS = (
    "manufacturer",
    "model",
    "generation",
    "year",
    "engine",
    "fuel",
    "transmission",
    "mileage",
    "reference_date",
    "conditions",
)
SELECT_COLUMNS = "id, owner_id, " + ", ".join(WRITABLE_COLUMNS)


def create_vehicle(owner_id, fields):
    """fields는 WRITABLE_COLUMNS의 모든 키를 가져야 합니다. 없는 값은 None으로 넘깁니다."""
    columns = ", ".join(("owner_id",) + WRITABLE_COLUMNS)
    placeholders = ", ".join(["%s"] * (len(WRITABLE_COLUMNS) + 1))
    values = (owner_id,) + tuple(fields[name] for name in WRITABLE_COLUMNS)
    with get_db().cursor() as cursor:
        cursor.execute(f"INSERT INTO vehicles ({columns}) VALUES ({placeholders})", values)
        return cursor.lastrowid


def list_vehicles_by_owner(owner_id):
    with get_db().cursor() as cursor:
        cursor.execute(
            f"SELECT {SELECT_COLUMNS} FROM vehicles WHERE owner_id = %s ORDER BY id",
            (owner_id,),
        )
        return cursor.fetchall()


def find_vehicle_for_owner(vehicle_id, owner_id):
    with get_db().cursor() as cursor:
        cursor.execute(
            f"SELECT {SELECT_COLUMNS} FROM vehicles WHERE id = %s AND owner_id = %s",
            (vehicle_id, owner_id),
        )
        return cursor.fetchone()
