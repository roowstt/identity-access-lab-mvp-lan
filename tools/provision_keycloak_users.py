"""Aprovisiona las cuentas demo del directorio en el realm activo de Keycloak."""
import os
import sys

import requests

KEYCLOAK = os.environ.get("KEYCLOAK_URL", "http://localhost:8081").rstrip("/")
REALM = "identity-access"
PASSWORDS = {
    "emp-001@securityteam.com": "C7d%gEMy9RW*UBHqTF", "emp-002@securityteam.com": "9zJI7o%RwfxvW@tDei",
    "emp-003@securityteam.com": "T0FY62kFJ$JPKRD*so", "emp-004@securityteam.com": "qPti*wJlcPgrzibcDn",
    "emp-005@securityteam.com": "!*s$@LgnBUcsT$Ookg", "emp-006@securityteam.com": "c4*3yxsDQt$X*4r9I%",
    "emp-007@securityteam.com": "RPra9mfSqeTpnDZqZ2", "emp-008@securityteam.com": "Y7o30!L$2b$c05m$tg",
    "emp-009@securityteam.com": "VYH$VD5VQ%i#wFZ9wQ", "emp-011@securityteam.com": "GSXPQMzQUHC6%S@@z@",
    "emp-012@securityteam.com": "XjFfvY0gOthoAEkze#", "emp-013@securityteam.com": "3ly@mKPocEeoEJXqcp",
    "emp-014@securityteam.com": "*%WRXUAMd1WrCxSrSi", "emp-015@securityteam.com": "!$v*mQN1U1P2xi8C6s",
    "emp-016@securityteam.com": "m210q*s*Rkv2pEp5NP", "emp-017@securityteam.com": "tx2UwUb9cm!kFSNikO",
    "emp-018@securityteam.com": "N#Y0c*EjEgx5g8$JwZ", "emp-019@securityteam.com": "xOAvOfl!oVKD5Qq$kc",
    "emp-020@securityteam.com": "wB8Q1zbCYzGoLiBmLX", "emp-021@securityteam.com": "la#baBuYro0m8$ZKRj",
    "emp-022@securityteam.com": "5j9fd855GExJIU@yt5", "emp-023@securityteam.com": "7Bpt2z5!OM3Kmbq2hu",
    "emp-024@securityteam.com": "5tmb6KAC28KM%cqt42", "emp-025@securityteam.com": "%i8uBvZp2v4ukfqM@e",
    "emp-026@securityteam.com": "ljljap9b3UyCdqo%Yk", "emp-027@securityteam.com": "yrFOvNVy5*yL9pXkmI",
    "emp-028@securityteam.com": "W7WZwtX%0xwQMKBcsP", "emp-029@securityteam.com": "BWKJHfE#uMygaMBz0D",
    "emp-030@securityteam.com": "usKkJ2NLgPE%QkF%@M", "emp-031@securityteam.com": "YNrXpsEQ6hYtThAGQT",
    "emp-032@securityteam.com": "!PvsB5Iqi%$4FRB7X!",
}

token = requests.post(f"{KEYCLOAK}/realms/master/protocol/openid-connect/token", data={
    "client_id": "admin-cli", "grant_type": "password", "username": os.environ["KEYCLOAK_ADMIN"], "password": os.environ["KEYCLOAK_ADMIN_PASSWORD"],
}, timeout=15).json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}
base = f"{KEYCLOAK}/admin/realms/{REALM}/users"

for email, password in PASSWORDS.items():
    found = requests.get(base, headers=headers, params={"username": email, "exact": "true"}, timeout=15).json()
    payload = {"username": email, "email": email, "emailVerified": True, "enabled": True, "credentials": [{"type": "password", "value": password, "temporary": False}]}
    if found:
        response = requests.put(f"{base}/{found[0]['id']}", headers=headers, json={**found[0], **payload}, timeout=15)
    else:
        response = requests.post(base, headers=headers, json=payload, timeout=15)
    response.raise_for_status()

print(f"{len(PASSWORDS)} cuentas aprovisionadas en {REALM}")
