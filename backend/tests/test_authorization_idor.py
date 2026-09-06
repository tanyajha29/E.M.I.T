import pytest
from datetime import datetime
from uuid import uuid4
from fastapi.testclient import TestClient

from app.main import app
from app.schemas.user import UserRole
from app.db.repositories.user_repository import UserRepository
from app.core.security import hash_password

client = TestClient(app)

pytestmark = pytest.mark.no_auth_override

def create_test_user(email: str, full_name: str, role: UserRole) -> tuple[dict, str]:
    user_repo = UserRepository()
    user_id = str(uuid4())
    user_doc = {
        "user_id": user_id,
        "email": email,
        "password_hash": hash_password("StrongPassword123!"),
        "full_name": full_name,
        "role": role.value,
        "badge_id": f"EMIT-TST-{user_id[:4].upper()}",
        "is_active": True,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    user_repo.create_user(user_doc)

    login_res = client.post("/auth/login", json={"email": email, "password": "StrongPassword123!"})
    token = login_res.json()["access_token"]
    return user_doc, token

def test_user_investigation_isolation_and_idor_protection():
    # 1. Setup User A and User B
    user_a, token_a = create_test_user("analyst.a@emit.local", "Analyst Alpha", UserRole.INVESTIGATOR)
    user_b, token_b = create_test_user("analyst.b@emit.local", "Analyst Bravo", UserRole.INVESTIGATOR)
    admin_u, token_admin = create_test_user("admin.sec@emit.local", "Admin Security", UserRole.ADMIN)

    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}
    headers_admin = {"Authorization": f"Bearer {token_admin}"}

    # 2. User A creates Case A
    res_a = client.post("/cases", json={"name": "Operation Alpha", "description": "Scope Alpha"}, headers=headers_a)
    assert res_a.status_code == 201
    case_a_id = res_a.json()["case_id"]

    # 3. User B creates Case B
    res_b = client.post("/cases", json={"name": "Operation Bravo", "description": "Scope Bravo"}, headers=headers_b)
    assert res_b.status_code == 201
    case_b_id = res_b.json()["case_id"]

    # 4. List Isolation: User A must see only Case A
    list_a = client.get("/cases", headers=headers_a)
    assert list_a.status_code == 200
    ids_a = [c["case_id"] for c in list_a.json()]
    assert case_a_id in ids_a
    assert case_b_id not in ids_a

    # 5. List Isolation: User B must see only Case B
    list_b = client.get("/cases", headers=headers_b)
    assert list_b.status_code == 200
    ids_b = [c["case_id"] for c in list_b.json()]
    assert case_b_id in ids_b
    assert case_a_id not in ids_b

    # 6. Admin sees both cases
    list_admin = client.get("/cases", headers=headers_admin)
    assert list_admin.status_code == 200
    ids_admin = [c["case_id"] for c in list_admin.json()]
    assert case_a_id in ids_admin
    assert case_b_id in ids_admin

    # =========================================================================
    # IDOR Tests: User B attempts to access User A's Case A & Child Resources
    # All must return 404 Not Found to prevent case existence enumeration
    # =========================================================================

    # Case details
    res_idor_get = client.get(f"/cases/{case_a_id}", headers=headers_b)
    assert res_idor_get.status_code == 404

    # Case update
    res_idor_put = client.put(f"/cases/{case_a_id}", json={"name": "Hacked Name"}, headers=headers_b)
    assert res_idor_put.status_code == 404

    # Case delete
    res_idor_del = client.delete(f"/cases/{case_a_id}", headers=headers_b)
    assert res_idor_del.status_code == 404

    # Case evidence listing
    res_idor_ev = client.get(f"/cases/{case_a_id}/evidence", headers=headers_b)
    assert res_idor_ev.status_code == 404

    # Case analysis listing
    res_idor_an = client.get(f"/cases/{case_a_id}/analyses", headers=headers_b)
    assert res_idor_an.status_code == 404

    # Case indicators listing
    res_idor_ind = client.get(f"/cases/{case_a_id}/indicators", headers=headers_b)
    assert res_idor_ind.status_code == 404

    # Case observations listing
    res_idor_obs = client.get(f"/cases/{case_a_id}/observations", headers=headers_b)
    assert res_idor_obs.status_code == 404

    # Case correlations listing
    res_idor_corr = client.get(f"/cases/{case_a_id}/correlations", headers=headers_b)
    assert res_idor_corr.status_code == 404

    # Case attack graph
    res_idor_graph = client.get(f"/cases/{case_a_id}/graph", headers=headers_b)
    assert res_idor_graph.status_code == 404

    # Case threat intel
    res_idor_ti = client.get(f"/cases/{case_a_id}/threat-intel", headers=headers_b)
    assert res_idor_ti.status_code == 404

    # Case risk assessment
    res_idor_risk = client.get(f"/cases/{case_a_id}/risk", headers=headers_b)
    assert res_idor_risk.status_code == 404

    # Case reports listing
    res_idor_rep = client.get(f"/cases/{case_a_id}/reports", headers=headers_b)
    assert res_idor_rep.status_code == 404

def test_viewer_role_case_assignment_and_restrictions():
    # Setup Investigator A and Viewer C
    user_a, token_a = create_test_user("inv.lead@emit.local", "Lead Investigator", UserRole.INVESTIGATOR)
    viewer_c, token_viewer = create_test_user("viewer.guest@emit.local", "Audit Viewer", UserRole.VIEWER)

    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_v = {"Authorization": f"Bearer {token_viewer}"}

    # 1. Viewer cannot create cases
    res_create = client.post("/cases", json={"name": "Viewer Prohibited"}, headers=headers_v)
    assert res_create.status_code == 403

    # 2. Investigator A creates Case A
    res_case = client.post("/cases", json={"name": "Confidential Op Alpha"}, headers=headers_a)
    assert res_case.status_code == 201
    case_id = res_case.json()["case_id"]

    # 3. Viewer does not see Case A initially
    list_initial = client.get("/cases", headers=headers_v)
    assert list_initial.status_code == 200
    assert len(list_initial.json()) == 0

    # 4. Investigator A assigns Viewer C to Case A
    assign_res = client.post(
        f"/cases/{case_id}/assign",
        json={"assigned_user_ids": [viewer_c["user_id"]]},
        headers=headers_a
    )
    assert assign_res.status_code == 200
    assert viewer_c["user_id"] in assign_res.json()["assigned_user_ids"]

    # 5. Viewer can now view Case A
    list_assigned = client.get("/cases", headers=headers_v)
    assert list_assigned.status_code == 200
    assert len(list_assigned.json()) == 1
    assert list_assigned.json()[0]["case_id"] == case_id

    # 6. Viewer can view case details
    view_res = client.get(f"/cases/{case_id}", headers=headers_v)
    assert view_res.status_code == 200

    # 7. Viewer CANNOT modify Case A (even when assigned)
    mod_res = client.put(f"/cases/{case_id}", json={"name": "Attempted Edit"}, headers=headers_v)
    assert mod_res.status_code == 404

    # 8. Viewer CANNOT delete Case A
    del_res = client.delete(f"/cases/{case_id}", headers=headers_v)
    assert del_res.status_code == 404
