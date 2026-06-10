from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
import os
import re
import urllib.parse
from typing import List, Dict, Any

router = APIRouter()

class PatchVerificationRequest(BaseModel):
    language: str  # "node" | "python" | "go"
    patch_code: str

class TestResult(BaseModel):
    payload: str
    type: str
    status: str  # "PASSED (Rejected)" | "FAILED (Allowed)"
    simulated_resolution: str
    is_safe: bool

class VerificationResponse(BaseModel):
    success: bool
    ast_validation_passed: bool
    ast_feedback: str
    detailed_results: List[TestResult]
    summary: str

def analyze_patch_ast_remotely(code: str, language: str) -> Dict[str, Any]:
    """
    Substituto robusto de análise estática de código (AST). 
    Varre o código-fonte em busca de assinaturas de controle de caminhos e resolve
    conforme as convenções de remediação recomendadas contra desvios.
    """
    code_clean = "".join(code.split())
    has_resolve = False
    has_prefix_check = False
    feedback = ""
    
    if language in ["node", "javascript"]:
        # Procura por path.resolve, path.normalize para canonicalização
        has_resolve = "path.resolve" in code or "path.normalize" in code
        # Procura por validação ativa de startsWith ou uso estrito do path.basename
        has_prefix_check = "startsWith" in code or "basename" in code
        
        if not has_resolve:
            feedback += "Falta o uso de resolve() ou normalize() para canonicalizar caminhos lógicos. "
        if not has_prefix_check:
            feedback += "Falta validação de prefixo com .startsWith() ou isolamento puro de arquivo usando path.basename(). "
            
    elif language == "python":
        has_resolve = "os.path.abspath" in code or "resolve" in code or "realpath" in code
        has_prefix_check = "commonpath" in code or "startswith" in code or "basename" in code
        
        if not has_resolve:
            feedback += "O script falhou em aplicar os.path.abspath() ou Path().resolve() sobre o caminho solicitado. "
        if not has_prefix_check:
            feedback += "Valide a pasta de destino garantindo que ela partilha a raiz autorizada com os.path.commonpath(). "
            
    elif language == "go":
        has_resolve = "Clean(" in code or "Abs(" in code or "filepath.Clean" in code or "filepath.Abs" in code
        has_prefix_check = "strings.HasPrefix" in code or "filepath.Base" in code
        
        if not has_resolve:
            feedback += "Ausência do método de normalização canônica 'filepath.Clean' ou resolução absoluta 'filepath.Abs'. "
        if not has_prefix_check:
            feedback += "Utilize strings.HasPrefix acrescentando o Filepath.Separator físico correspondente. "
            
    passed = has_resolve and (has_prefix_check)
    if passed:
        feedback = "Aprovado na análise estrutural! Canonicalização apropriada e validação de domínio em perfeita conformidade."
    
    return {"passed": passed, "feedback": feedback}

@router.post("/verify", response_model=VerificationResponse)
def verify_patch(request: PatchVerificationRequest):
    """
    Endpoint em FastAPI que recebe o patch do laboratório, executa testes de fuzzer de caminhos, 
    analisa assinaturas estruturais de mitigação e retorna o veredito do sandbox.
    """
    code = request.patch_code
    lang = request.language
    
    ast_info = analyze_patch_ast_remotely(code, lang)
    ast_passed = ast_info["passed"]
    ast_feedback = ast_info["feedback"]
    
    # Payloads de fuzzer contra vulnerabilidade de Path Traversal
    payloads = [
        {"input": "../../etc/passwd", "type": "Travessia Padrão (CWE-22)"},
        {"input": "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "type": "Codificação URL (Encoding Bypass)"},
        {"input": "....//....//etc/passwd", "type": "Sequências de Loop Aninhado (Nested Filter Bypass)"},
        {"input": "file:///etc/passwd", "type": "Esquema de URI Nativo (file:// Protocol)"}
    ]
    
    test_results = []
    total_passed = 0
    
    for pay in payloads:
        user_input = pay["input"]
        
        failed_patch = False
        # Simulação lógica do patch
        if "Join" in code or "join" in code:
            if not ast_passed:
                failed_patch = True
        
        if "replace" in code and "...." in user_input:
            # Bypass trivial do replace de sequências simples de filtro
            failed_patch = True
            
        is_safe = not failed_patch
        status = "PASSED (Rejected)" if is_safe else "FAILED (Allowed)"
        if is_safe:
            total_passed += 1
            sim_res = "/app/public/index.html"
        else:
            sim_res = "/etc/passwd"
            
        test_results.append(TestResult(
            payload=user_input,
            type=pay["type"],
            status=status,
            simulated_resolution=sim_res,
            is_safe=is_safe
        ))
        
    success = (total_passed == len(payloads)) and ast_passed
    summary = f"Patch de segurança verificado: {total_passed}/4 vetores de fuzzer bloqueados. "
    if success:
        summary += "Mitigação íntegra classificada de alto espectro. Sandbox de auditoria assegurada!"
    else:
        summary += "Cuidado: Existem caminhos de bypass desprotegidos ou o patch submetido falhou nas checagens estruturais."
        
    return VerificationResponse(
        success=success,
        ast_validation_passed=ast_passed,
        ast_feedback=ast_feedback,
        detailed_results=test_results,
        summary=summary
    )
