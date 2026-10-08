from backend.services.simulator import get_scenario_definition
from backend.services.risk_engine import evaluate_security_risk

def run_check():
    for sid in ['normal_activity', 'repeated_logins', 'api_burst', 'sensitive_access', 'large_download', 'compromised_account']:
        ev = get_scenario_definition(sid)['data']
        # Ensure scenario_type is stripped or does not affect evaluation
        ev_clean = dict(ev)
        ev_clean.pop('scenario_type', None)
        res = evaluate_security_risk(ev_clean)
        print(f"[{sid}]")
        print(f"  Prediction:      {res['prediction']}")
        print(f"  Risk Score:      {res['risk_score']} ({res['risk_level']})")
        print(f"  Anomaly Score:   {res['anomaly_score']}")
        print(f"  Detected Factor: {res['detected_behaviour']}")
        print(f"  Reason excerpt:  {res['reason'][:90]}...")
        print()

if __name__ == '__main__':
    run_check()
