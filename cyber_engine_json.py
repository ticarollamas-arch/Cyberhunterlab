#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import random
import json
import time

ARQUIVO_MEMORIA = "hunter_state.json"

def carregar_estado():
    if os.path.exists(ARQUIVO_MEMORIA):
        try:
            with open(ARQUIVO_MEMORIA, 'r') as f:
                return json.load(f)
        except:
            pass
    return {"iteration": 0, "chain_id": random.randint(1000, 9999)}

def salvar_estado(dados):
    with open(ARQUIVO_MEMORIA, 'w') as f:
        json.dump(dados, f, indent=4)

def gerar_poc_dados():
    estado = carregar_estado()
    estado["iteration"] += 1
    
    # Mutação e geração dos dados técnicos brutos (Vetor Dinâmico)
    seed = estado["iteration"]
    payload_math_inversion = -(15000 + (seed * 37))
    payload_infra_division = 0 if seed % 2 == 1 else 1024
    
    # Montagem da Cadeia de Dependência de Vulnerabilidades (Exploit Chain)
    poc_output = {
        "cyber_hunter_lab_version": "2.5.0-core",
        "export_timestamp": int(time.time()),
        "audit_session": {
            "chain_id": f"CHL-CHAIN-{estado['chain_id']}",
            "sequence_step": estado["iteration"],
            "target_architecture": "x86_64_bits_infrastructure"
        },
        "vulnerability_chain": [
            {
                "step": 1,
                "vulnerability_type": "Path_Traversal",
                "cwe_id": "CWE-22",
                "severity": "HIGH",
                "execution_vector": {
                    "input_field": "url_parameter",
                    "payload": "../../../etc/config.json",
                    "status_code": 200,
                    "leaked_data_reference": "database_credentials_block"
                }
            },
            {
                "step": 2,
                "vulnerability_type": "Mathematical_Logic_Bypass",
                "cwe_id": "CWE-697",
                "severity": "CRITICAL",
                "execution_vector": {
                    "input_field": "coupon_code_input",
                    "payload": payload_math_inversion,
                    "mathematical_effect": "inverse_subtraction_addition",
                    "impact_metrics": {
                        "simulated_leak_value": abs(payload_math_inversion),
                        "integrity_compromised": True
                    },
                    "patch_remediation": {
                        "target_file": "billing_engine.py",
                        "validation_logic": "if coupon_code_input < 0:\n    raise ValueError(\"Valor negativo não permitido no gateway\")"
                    }
                }
            },
            {
                "step": 3,
                "vulnerability_type": "Denial_of_Service_Infrastructure",
                "cwe_id": "CWE-369",
                "severity": "HIGH",
                "execution_vector": {
                    "input_field": "load_balancer_divisor",
                    "payload": payload_infra_division,
                    "exception_raised": "ZeroDivisionError" if payload_infra_division == 0 else "None",
                    "system_state": "CRASH" if payload_infra_division == 0 else "STABLE",
                    "patch_remediation": {
                        "target_file": "infrastructure_balancer.py",
                        "validation_logic": "if load_balancer_divisor <= 0:\n    raise ValueError(\"Divisor inválido ou nulo\")"
                    }
                }
            }
        ]
    }
    
    salvar_estado(estado)
    return poc_output

if __name__ == "__main__":
    resultado = gerar_poc_dados()
    # Grava o resultado para que o front-end ou o CLI consuma
    with open("hunter_poc_audit.json", "w", encoding="utf-8") as f:
        json.dump(resultado, f, indent=4, ensure_ascii=False)
    
    # Imprime no terminal o JSON para auditoria rápida
    print(json.dumps(resultado, indent=4, ensure_ascii=False))
