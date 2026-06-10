#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cyber Hunter Lab Report Generator (CLI Edition)
Author: Ana Caroline Lamas (Senior Security Architect)
Description: Air-gapped executive report generator mapping mathematical vulnerabilities to economic impact.
Licensed under Enterprise VRP Compliance Agreement (2026).
"""

import sys
import os
import json
from datetime import datetime

# Imporar bibliotecas Rich ou definir fallbacks seguros se não estiver instalado
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.columns import Columns
    from rich.theme import Theme
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# Tema customizado de altíssima fidelidade de cores para a diretoria corporativa
CUSTOM_THEME = {
    "brand": "bold #10b981", # Emerald
    "danger": "bold #ef4444", # Red
    "warning": "bold #f59e0b", # Orange
    "info": "bold #3b82f6", # Blue
    "muted": "#71717a", # Zinc-500
    "white": "bold #ffffff",
    "accent": "#a7f3d0" # Soft green
}

# Tradução e mapeamento de riscos de negócio atrelados ao CWE
CWE_BUSINESS_RISK = {
    "CWE-22": {
        "title": "Vazamento Crítico de Arquivos e Chaves (Path Traversal / CWE-22)",
        "risk_desc": "Violação severa do isolamento de diretórios da planta digital. Permite que atores maliciosos injetem sequências de travessia (ex: '../../') para desviar de barreiras de API e vazar segredos fundamentais (como credentials_blocks, chaves privadas ou arquivos confidenciais do sistema operacional).",
        "impact": "Exposição total de segredos de banco de dados e potencial escalada para preempção de infraestrutura."
    },
    "CWE-697": {
        "title": "Bypass de Lógica Matemática no Faturamento (Cwe-697)",
        "risk_desc": "Falha crítica de comparação lógica e integridade de operadores numéricos no checkout ou billing engines. Permite a injeção de valores inteiros negativos para inverter operações de subtração, forçando saldos credores fictícios e subtrações indevidas na receita transacional da empresa.",
        "impact": "Subversão fraudulenta de faturamento com perdas financeiras diretas imediatas e cumulativas por transação."
    },
    "CWE-369": {
        "title": "Negação de Serviço Estrutural via Divisão por Zero (Cwe-369)",
        "risk_desc": "Ausência de tratamento de exceções de divisão e limites numéricos baixos na camada de balanceamento de carga de rede. Atacantes enviando payloads simplificados ou nulos acionam exceções fatais não gerenciadas nas threads, provocando perda imediata de responsividade de rede.",
        "impact": "Inoperabilidade total dos serviços digitais corporativos (Crash de produção), acarretando indisponibilidade para clientes legítimos."
    }
}

class CyberHunterReporter:
    def __init__(self, filepath=None, json_data=None):
        self.filepath = filepath
        self.raw_data = json_data
        self.console = Console(theme=Theme(CUSTOM_THEME)) if HAS_RICH else None

    def output_plain_text(self, report):
        """Fallback elegante caso o Rich não esteja presente."""
        print("="*80)
        print("         CYBER HUNTER LAB REPORT GENERATOR - EXECUTIVE TRANSLATION")
        print("="*80)
        print(f"Sessão de Auditoria: {report['chain_id']} (v{report['version']})")
        print(f"Timestamp: {report['date']}\n")
        
        print("-" * 80)
        print("[1. SUMÁRIO EXECUTIVO - PARA A DIRETORIA]")
        print("-" * 80)
        print(f"🛡️  Identificador Único: {report['chain_id']}")
        print(f"💰 Risco de Desfalque Imediato: {report['financial_risk']}")
        print(f"⚡ Status de Integridade: {report['system_integrity']}")
        print(f"⚠️  Gravidade Máxima: {report['max_severity']}")
        print(f"📝 Nota de Negócio: {report['executive_overview']}")
        print("\n" + "-" * 80)
        print("[2. MAPEAMENTO DE CONFORMIDADE GLOBAL]")
        print("-" * 80)
        for cwe in report['compliance']:
            print(f"• {cwe['id']} ({cwe['vulnerability']}) -> Risco: {cwe['severity']}")
            print(f"  Negócio: {cwe['business_description']}")
            print(f"  Remediação Recomendada em {cwe['target_file']}:")
            print(f"  {cwe['remediation_logic']}\n")
            
        print("-" * 80)
        print("[3. PROVA DE CONCEITO SEQUENCIAL (CADEIA DE EVIDÊNCIAS)]")
        print("-" * 80)
        for step in report['evidence_chain']:
            print(f"Passo {step['step']}: {step['vuln_type']} ({step['severity']})")
            print(f"  Vetor de Entrada: {step['input_field']} | Payload: {step['payload']}")
            print(f"  Efeito Comportamental: {step['effect']}\n")
            
        print("-" * 80)
        print("[4. VALIDAÇÃO E DIAGNÓSTICO BEHAVIORAL]")
        print("-" * 80)
        print(report['behavioral_diagnosis'])
        print("="*80)

    def load_payload(self):
        if self.raw_data:
            return self.raw_data
        
        if not self.filepath:
            raise ValueError("Caminho do arquivo JSON não especificado.")
            
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"Arquivo não localizado no caminho: {self.filepath}")
            
        with open(self.filepath, 'r', encoding='utf-8') as f:
            return json.load(f)

    def generate_report_structure(self):
        data = self.load_payload()
        
        session_info = data.get("audit_session", {})
        chain_id = session_info.get("chain_id", "DESCONHECIDO")
        vulns = data.get("vulnerability_chain", [])
        version = data.get("cyber_hunter_lab_version", "2.5.0-core")
        
        # Calcular impacto financeiro direto baseado nas transações
        total_leak_value = 0
        system_state = "NORMAL"
        max_severity = "LOW"
        severity_priority_map = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        
        for v in vulns:
            # Pegar simulated leak value
            vector = v.get("execution_vector", {})
            metrics = vector.get("impact_metrics", {})
            val = metrics.get("simulated_leak_value", 0)
            total_leak_value += val
            
            # Estado do sistema
            state = vector.get("system_state", "STABLE")
            if state == "CRASH":
                system_state = "CRASH"
                
            # Severidade máxima
            sev = v.get("severity", "LOW")
            if severity_priority_map.get(sev, 1) > severity_priority_map.get(max_severity, 1):
                max_severity = sev

        # Formatar corretor de valores local
        financial_risk_str = f"R$ {total_leak_value:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".") if total_leak_value > 0 else "R$ 0,00"
        
        status_infra = "ALERTA: Risco de Parada Total (Crash Estrutural)" if system_state == "CRASH" \
            else "POTENCIAL COMPROMETIMENTO DE DADOS"
            
        # 1. Sumário Executivo Textual
        exec_desc = (
            f"A auditoria de segurança determinou vulnerabilidades interligadas que expõem "
            f"a planta analítica a desfalques financeiros diretos de {financial_risk_str} por transação fraudulenta. "
            f"Em paralelo, a ausência de isolamento seguro expõe credenciais confidenciais, "
            f"e payloads de negação de serviço levam a infraestrutura ao status de {system_state}."
        )
        
        # 2. Compliance
        compliance_items = []
        for v in vulns:
            cwe_id = v.get("cwe_id", "Desconhecido")
            vuln_type = v.get("vulnerability_type", "Lógica Indeterminada")
            vector = v.get("execution_vector", {})
            remed = vector.get("patch_remediation", {})
            
            cwe_info = CWE_BUSINESS_RISK.get(cwe_id, {
                "title": f"Risco Lógico Geral ({cwe_id})",
                "risk_desc": "Brecha de validação comportamental em componentes internos expostos.",
                "impact": "Exposição geral e riscos de escalonamento tecnológico."
            })
            
            compliance_items.append({
                "id": cwe_id,
                "vulnerability": vuln_type,
                "severity": v.get("severity", "HIGH"),
                "business_description": cwe_info["risk_desc"],
                "target_file": remed.get("target_file", "API_Engine.py"),
                "remediation_logic": remed.get("validation_logic", "Valide todas as entradas de contadores nas pontas.")
            })
            
        # 3. Evidence Chain
        evidence_chain = []
        for index, v in enumerate(vulns):
            vector = v.get("execution_vector", {})
            effect = "Exposição de segredo de credenciais externas"
            if "mathematical_effect" in vector:
                effect = f"Inversão matemática ({vector['mathematical_effect']}) com desfalque direto de receita"
            elif "exception_raised" in vector:
                effect = f"Lançamento de {vector['exception_raised']} induzindo status generalizado de {vector.get('system_state', 'CRASH')}"
                
            evidence_chain.append({
                "step": v.get("step", index + 1),
                "vuln_type": v.get("vulnerability_type", "Mitigada Lógica"),
                "severity": v.get("severity", "HIGH"),
                "input_field": vector.get("input_field", "campo_ativo"),
                "payload": str(vector.get("payload", "")),
                "effect": effect
            })
            
        # 4. Behavioral Diagnosis
        diagnosis = (
            "A auditoria comportamental realizada sob injeção de estados e análise determinística comprovou "
            "que a planta lógica da empresa carece de filtros de integridade nas APIs públicas de faturamento e infraestrutura.\n"
            "Não foram detectadas assinaturas ativas de sanitização canônica nos limites de diretório, e o billing engine aceita "
            "entradas negativas que subvertem as equações de custos.\n"
            "Recomenda-se enfaticamente que a equipe de engenharia adote os patches de segurança delineados no Sumário de "
            "Remediação deste relatório para restabelecer a integridade defensiva corporativa."
        )
        
        timestamp_epoch = data.get("export_timestamp", int(datetime.now().timestamp()))
        date_formatted = datetime.fromtimestamp(timestamp_epoch).strftime('%Y-%m-%d %H:%M:%S UTC')
        
        return {
            "version": version,
            "chain_id": chain_id,
            "date": date_formatted,
            "financial_risk": f"{financial_risk_str} por transação explorada" if total_leak_value > 0 else "Indeterminado / Vazamento de Dados Críticos",
            "system_integrity": status_infra,
            "max_severity": max_severity,
            "executive_overview": exec_desc,
            "compliance": compliance_items,
            "evidence_chain": evidence_chain,
            "behavioral_diagnosis": diagnosis
        }

    def render(self):
        try:
            report = self.generate_report_structure()
        except Exception as e:
            if HAS_RICH:
                self.console.print(f"[bold red]Erro ao processar payload de auditoria: {str(e)}[/bold red]")
            else:
                print(f"Erro ao processar payload: {str(e)}")
            return
            
        if not HAS_RICH:
            self.output_plain_text(report)
            return
            
        c = self.console
        
        # Cabeçalho Geral
        c.print()
        c.print(Panel.fit(
            f" [white]VULNERABILITY AUDIT REPORT GENERATOR[/white] [muted]v{report['version']}[/muted] \n"
            f" [brand]Mecanismo de Proteção de Receita & Análise C-Suite[/brand] \n"
            f" [white]SESSÃO:[/white] [brand]{report['chain_id']}[/brand]  |  [white]DATA:[/white] {report['date']} ",
            border_style="brand",
            title="[brand]CYBER HUNTER LAB[/brand]",
            subtitle="[white]Strictly Confidential - Internal Only[/white]"
        ))
        
        # 1. Sumário Executivo
        c.print()
        c.print("[brand]╔════════════════════════════════════════════════════════════════════════════════╗[/brand]")
        c.print("[brand]║ 1. SUMÁRIO EXECUTIVO (C-SUITE HIGHLIGHTS)                                      ║[/brand]")
        c.print("[brand]╚════════════════════════════════════════════════════════════════════════════════╝[/brand]")
        
        summary_panel = Panel(
            f"[white]• IDENTIFICADOR ÚNICO DA AUDITORIA:[/white] [brand]{report['chain_id']}[/brand]\n"
            f"[white]• RISCO FINANCEIRO IMEDETO COMPUTADO:[/white] [danger]{report['financial_risk']}[/danger]\n"
            f"[white]• ESTADO DE INTEGRIDADE OPERACIONAL:[/white] [danger]{report['system_integrity']}[/danger]\n"
            f"[white]• SEVERIDADE DA ENTRADA DE VULNERABILIDADE:[/white] [danger]{report['max_severity']}[/danger]\n\n"
            f"[white]• PARECER OPERACIONAL:[/white] {report['executive_overview']}",
            border_style="danger" if report['max_severity'] in ["HIGH", "CRITICAL"] else "warning",
            title="[danger]MEDIÇÃO DE RISCO FINANCEIRO & ATIVOS[/danger]"
        )
        c.print(summary_panel)
        
        # 2. Mapeamento de Conformidade Global
        c.print()
        c.print("[brand]╔════════════════════════════════════════════════════════════════════════════════╗[/brand]")
        c.print("[white]║ 2. MAPEAMENTO DE CONFORMIDADE GLOBAL (TECHNICAL COMPLIANCE)                    ║[/white]")
        c.print("[brand]╚════════════════════════════════════════════════════════════════════════════════╝[/brand]")
        
        table = Table(show_header=True, header_style="brand", border_style="muted", expand=True)
        table.add_column("CWE ID", style="brand", width=12)
        table.add_column("Vulnerabilidade", style="white", width=22)
        table.add_column("Severidade", style="danger", width=12)
        table.add_column("Mapeamento de Impacto Teórico / Proteção Secundária", style="white")
        
        for v in report['compliance']:
            table.add_row(
                v["id"],
                v["vulnerability"],
                v["severity"],
                v["business_description"]
            )
            
        c.print(table)
        
        # Subtabela de Remediação Concreta
        c.print()
        c.print("[accent]» Código de Validação das APIs (Filtros de Proteção Recomendados):[/accent]")
        remed_table = Table(show_header=True, header_style="accent", border_style="muted", expand=True)
        remed_table.add_column("Arquivo de Produção", style="brand", width=25)
        remed_table.add_column("Estrutura Lógica Recomendada (Patches)", style="white")
        
        for v in report['compliance']:
            remed_table.add_row(
                v["target_file"],
                v["remediation_logic"]
            )
        c.print(remed_table)
        
        # 3. Cadeia de Evidências Sequenciais
        c.print()
        c.print("[brand]╔════════════════════════════════════════════════════════════════════════════════╗[/brand]")
        c.print("[white]║ 3. PROVA DE CONCEITO SEQUENCIAL (EVIDENCE PIPELINE CHAIN)                      ║[/white]")
        c.print("[brand]╚════════════════════════════════════════════════════════════════════════════════╝[/brand]")
        
        for item in report['evidence_chain']:
            step_panel = Panel(
                f"[white]Vetor de Injeção:[/white] [accent]{item['input_field']}[/accent]  |  "
                f"[white]Payload de Mutação:[/white] [danger]{item['payload']}[/danger]\n"
                f"[white]Efeito no Backend:[/white] [warning]{item['effect']}[/warning]",
                title=f"[white]Passo {item['step']}:[/white] [danger]{item['vuln_type']} ({item['severity']})[/danger]",
                border_style="danger" if item['severity'] in ["HIGH", "CRITICAL"] else "warning"
            )
            c.print(step_panel)
            
        # 4. Diagnóstico Comportamental
        c.print()
        c.print("[brand]╔════════════════════════════════════════════════════════════════════════════════╗[/brand]")
        c.print("[white]║ 4. PARECER E DIAGNÓSTICO BEHAVIORAL (AUDITORIA FINAL)                          ║[/white]")
        c.print("[brand]╚════════════════════════════════════════════════════════════════════════════════╝[/brand]")
        
        diag_panel = Panel(
            report['behavioral_diagnosis'],
            border_style="brand",
            title="[brand]VALIDAÇÃO FINAL SEM BUROCRACIA[/brand]"
        )
        c.print(diag_panel)
        c.print()

def main():
    if len(sys.argv) < 2:
        print("\n [bold red]Erro: Parâmetro ausente.[/bold red]" if HAS_RICH else "\n Erro: Parâmetro ausente.")
        print(" Uso correto:")
        print("   python cyber_hunter_lab_cli.py [caminho_do_payload.json]\n")
        
        # Gerar um payload padrão caso o usuário não passe nenhum, para fins de demonstração rápida
        demodata = {
          "cyber_hunter_lab_version": "2.5.0-core",
          "export_timestamp": 1780935637,
          "audit_session": {
            "chain_id": "CHL-CHAIN-9521",
            "sequence_step": 2,
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
                "payload": -15074,
                "mathematical_effect": "inverse_subtraction_addition",
                "impact_metrics": {
                  "simulated_leak_value": 15074,
                  "integrity_compromised": true
                },
                "patch_remediation": {
                  "target_file": "billing_engine.py",
                  "validation_logic": "if coupon_code_input < 0: raise ValueError()"
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
                "payload": 0,
                "exception_raised": "ZeroDivisionError",
                "system_state": "CRASH",
                "patch_remediation": {
                  "target_file": "infrastructure_balancer.py",
                  "validation_logic": "if load_balancer_divisor <= 0: raise Exception()"
                }
              }
            }
          ]
        }
        print(" Rodando com payload de amostra devido a parâmetro vazio...\n")
        reporter = CyberHunterReporter(json_data=demodata)
        reporter.render()
        sys.exit(0)
        
    filepath = sys.argv[1]
    
    # Se o parâmetro for "--help" ou "-h"
    if filepath in ["--help", "-h"]:
        print("Cyber Hunter Lab Report Generator CLI Tool")
        print("Como usar: python cyber_hunter_lab_cli.py [caminho_do_arquivo.json]")
        sys.exit(0)
        
    try:
        reporter = CyberHunterReporter(filepath=filepath)
        reporter.render()
    except Exception as e:
        print(f"Erro Fatal: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
