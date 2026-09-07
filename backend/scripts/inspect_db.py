import sys
import os
sys.path.insert(0, os.path.abspath('.'))

from app.db.repositories.case_repository import CaseRepository
from app.db.repositories.analysis_run_repository import AnalysisRunRepository
from app.db.repositories.observation_repository import ObservationRepository
from app.db.repositories.indicator_repository import IndicatorRepository
from app.db.repositories.correlation_repository import CorrelationRepository
from app.db.repositories.risk_repository import RiskRepository
from app.db.repositories.attack_repository import AttackNodeRepository, AttackEdgeRepository

def main():
    cr = CaseRepository()
    ar = AnalysisRunRepository()
    obs_repo = ObservationRepository()
    ind_repo = IndicatorRepository()
    corr_repo = CorrelationRepository()
    risk_repo = RiskRepository()
    node_repo = AttackNodeRepository()
    edge_repo = AttackEdgeRepository()

    print("=== CASES ===")
    cases = cr.find_all({})
    for c in cases:
        print(f"Case ID: {c.get('case_id')} | Name: '{c.get('name')}' | Status: {c.get('status')}")

    print("\n=== ANALYSES ===")
    analyses = ar.find_all({})
    for a in analyses:
        print(f"Analysis ID: {a.get('analysis_id')} | Case ID: {a.get('case_id')} | Status: {a.get('status')} | Type: {a.get('analysis_type')}")

if __name__ == '__main__':
    main()
