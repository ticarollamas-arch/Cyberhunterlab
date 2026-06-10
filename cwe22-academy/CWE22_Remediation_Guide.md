# Manual Técnico de Remediação CWE-22 (Path Traversal / Directory Traversal)

Este documento descreve os padrões canônicos de segurança para blindar aplicações que realizam leitura e escrita em sistemas de arquivos contra manipulações de caminhos por usuários mal-intencionados.

---

## 1. Compreensão do Risco (A Ameaça CWE-22)

O **Path Traversal** (Travessia de Diretório) ocorre quando entradas externas controladas por usuários finais (parâmetros de URL, corpo de formulários, cabeçalhos HTTP, metadados de arquivos) são utilizadas cruamente para mapear endereços de arquivos físicos no sistema operacional hospedeiro. 

Ao injetar caracteres de retrocesso lógicos relativos (`../` ou `..\`), atacantes elevam seus privilégios de acesso a arquivos de configuração fundamentais contidos fora da sub-raiz pública, permitindo o vazamento de segredos e escalada de privilégios para execuções remotas (RCE).

## 2. Tipos Comuns de Bypass contra Filtros Fracos

### 2.1 Nested Sequences (Sequências de Filtragem Aninhadas)
* **Filtro Fraco:** Remover recursiva ou simplesmente `../` via string replace simples (ex: `input.replace("../", "")`).
* **Vetor de Bypass:** `....//....//etc/passwd`
* **Mecânica:** O primeiro replace remove os caracteres centrais mais internos `../`. A string adjacente une-se novamente formando uma sequência perfeita de retrocesso.

### 2.2 Codificação Dupla / URL Encoding Obfuscation
* **Filtro Fraco:** Regex bloqueando caracteres literais de barra `/` e ponto `.`.
* **Vetor de Bypass:** `%2e%2e%2f%2e%2e%2fetc%2fpasswd` ou em formato duplo `%252e%252e%252f`.
* **Mecânica:** O validador vê apenas caracteres seguros alfanuméricos na entrada HTTP original. Quando a string atinge o framework nativo de sistema de arquivos posterior, ela é auto-decodificada e processada como travessia válida.

### 2.3 Protocolos Nativos de URI
* **Filtro Fraco:** Inspeção apenas do prefixo físico do diretório.
* **Vetor de Bypass:** `file:///etc/passwd`
* **Mecânica:** O resolvedor nativo analisa o cabeçalho do esquema RFC, alternado o motor de busca sobre os limites físicos.

---

## 3. Padrões de Correção por Linguagem

### Padrão Conforme em Node.js (V8)
```javascript
const path = require('path');

function getSafeDiskPath(baseFolder, userInput) {
    // 1. Resolve o caminho base em formato absoluto inabalável
    const absoluteRoot = path.resolve(baseFolder);
    
    // 2. Resolve a junção contendo a instrução do usuário
    const resolvedPath = path.resolve(absoluteRoot, userInput);
    
    // 3. Garante que o caminho final começa com a raiz mais o caractere de barreira física
    if (!resolvedPath.startsWith(absoluteRoot + path.sep)) {
        throw new Error("Aviso de Segurança: Violação de limites de pasta restrita.");
    }
    
    return resolvedPath;
}
```

### Padrão Conforme em Python
```python
import os

def check_safe_local_path(base_dir, user_input):
    # 1. Torna a pasta raiz absoluta
    abs_root = os.path.abspath(base_dir)
    
    # 2. Une e resolve completamente links simbólicos
    resolved_path = os.path.abspath(os.path.join(abs_root, user_input))
    
    # 3. Usa os.path.commonpath para garantir a herança íntegra do diretório comum
    common = os.path.commonpath([abs_root, resolved_path])
    if common != abs_root:
        raise PermissionError("Bloqueio de Segurança: O caminho solicitado escapou da pasta raiz.")
        
    return resolved_path
```

### Padrão Conforme em Golang (Go)
```go
package security

import (
	"errors"
	"path/filepath"
	"strings"
)

func ResolveSafePath(baseRoot, userInput string) (string, error) {
	// 1. Avalia o caminho físico absoluto do diretório-base
	absRoot, err := filepath.Abs(baseRoot)
	if err != nil {
		return "", err
	}

	// 2. Limpa e resolve caminhos aninhados lógicos
	cleanTargetPath := filepath.Clean(filepath.Join(absRoot, userInput))

	// 3. Valida se possui o prefixo exato da pasta raiz restrita
	if !strings.HasPrefix(cleanTargetPath, absRoot+string(filepath.Separator)) {
		return "", errors.New("access denied: parent path resolution is forbidden")
	}

	return cleanTargetPath, nil
}
```
