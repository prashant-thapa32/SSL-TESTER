from datetime import datetime

def days_until(expiry_date):
    now = datetime.utcnow()
    return (expiry_date - now).days

