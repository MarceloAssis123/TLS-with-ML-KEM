# TLS with ML-KEM

Implementação de criptografia híbrida usando **ML-KEM-768** (post-quantum) + **AES-GCM-256** para Node.js.

## Requisitos

- **Node.js >= 24.7.0** (para suporte a ML-KEM no WebCrypto API)
- Sem dependências externas

## Sobre a Implementação

Este módulo fornece 5 funções principais para criptografia híbrida:

### 1. `generateK(): Promise<CryptoKey>`
Gera uma chave simétrica AES-GCM-256 para criptografia de dados.

### 2. `encapsulateK(recipientPublicKey, K): Promise<EncapsulatedK>`
Encapsula a chave K usando ML-KEM-768. Retorna:
- `kemCiphertextB64`: Ciphertext do ML-KEM
- `wrapIvB64`: IV usado para cifrar K
- `wrappedKB64`: K cifrada com a chave de wrapping

### 3. `decapsulateK(recipientPrivateKey, data): Promise<CryptoKey>`
Recupera a chave K original usando a chave privada ML-KEM.

### 4. `aesEncryptText(K, plaintext): Promise<AesEncryptedText>`
Criptografa texto usando AES-GCM com a chave K.

### 5. `aesDecryptText(K, data): Promise<string>`
Descriptografa texto usando AES-GCM com a chave K.

## Como Usar

```typescript
import { webcrypto } from "node:crypto";
import {
  generateK,
  encapsulateK,
  decapsulateK,
  aesEncryptText,
  aesDecryptText
} from "./mlkem_aes.ts";

// 1. Destinatário gera par de chaves ML-KEM-768
const bobKeyPair = await webcrypto.subtle.generateKey(
  "ML-KEM-768",
  true,
  ["encapsulateKey", "decapsulateKey"]
);

// 2. Remetente gera chave simétrica K
const K = await generateK();

// 3. Remetente encapsula K com chave pública do destinatário
const encapsulated = await encapsulateK(bobKeyPair.publicKey, K);

// 4. Destinatário recupera K com sua chave privada
const recoveredK = await decapsulateK(bobKeyPair.privateKey, encapsulated);

// 5. Remetente criptografa mensagem
const encrypted = await aesEncryptText(K, "Hello, World!");

// 6. Destinatário descriptografa com K recuperada
const decrypted = await aesDecryptText(recoveredK, encrypted);

console.log(decrypted); // "Hello, World!"
```

> **Importante**: Use `webcrypto.subtle` diretamente, não desestruture `const { subtle } = webcrypto`. A desestruturação remove o binding do contexto `this` necessário para os métodos WebCrypto funcionarem corretamente.

## Executar Exemplo

Se você tiver Node.js 24.7.0+:

```bash
# Executar exemplo completo (recomendado)
node --experimental-strip-types example.ts

# Ou compilar primeiro
npm run build
node dist/example.js
```

### Saída Esperada

```
================================================================================
Exemplo: ML-KEM-768 + AES-GCM-256 Criptografia Híbrida
================================================================================

📋 Passo 1: Bob gera par de chaves ML-KEM-768
✅ Par de chaves ML-KEM-768 gerado com sucesso

📋 Passo 2: Alice gera chave simétrica K (AES-GCM-256)
✅ Chave K gerada com sucesso

📋 Passo 3: Alice encapsula K com chave pública de Bob
✅ Encapsulamento concluído

📋 Passo 4: Bob decapsula e recupera K com sua chave privada
✅ Chave K recuperada com sucesso

📋 Passo 5: Alice criptografa mensagem com K
✅ Mensagem criptografada

📋 Passo 6: Bob descriptografa mensagem com K recuperada
✅ Mensagem descriptografada com sucesso

================================================================================
✅ SUCESSO! A mensagem foi recuperada corretamente.
✅ K original e recoveredK são criptograficamente equivalentes.
================================================================================
```

## Considerações de Implementação

### Contexto WebCrypto

Este módulo usa `webcrypto.subtle` e `webcrypto.getRandomValues` diretamente, sem desestruturação. Isso é **essencial** porque:

- A desestruturação (`const { subtle } = webcrypto`) remove o binding do contexto `this`
- Métodos WebCrypto precisam do contexto correto para acessar APIs nativas
- Usar `webcrypto.subtle.method()` mantém o binding automático do JavaScript

**❌ Incorreto:**
```typescript
const { subtle, getRandomValues } = webcrypto;
await subtle.generateKey(...); // ❌ Erro: "Value of 'this' must be of type Crypto"
```

**✅ Correto:**
```typescript
await webcrypto.subtle.generateKey(...); // ✅ Funciona corretamente
```

### Key Usages ML-KEM

Para gerar pares de chaves ML-KEM-768:

```typescript
const keyPair = await webcrypto.subtle.generateKey(
  "ML-KEM-768",
  true,
  ["encapsulateKey", "decapsulateKey"] // ✅ Correto
);
```

As chaves geradas automaticamente terão os usages corretos:
- Chave pública: `["encapsulateKey"]`
- Chave privada: `["decapsulateKey"]`

## Nota Criptográfica

**ML-KEM** (Module-Lattice-Based Key Encapsulation Mechanism) é um KEM, não um algoritmo de cifra tradicional. Isso significa que:

- ML-KEM não cifra diretamente dados arbitrários
- ML-KEM gera uma chave compartilhada aleatória (wrappingKey) + ciphertext
- Usamos essa wrappingKey para cifrar a chave K escolhida via AES-GCM
- O destinatário usa o ciphertext para derivar a mesma wrappingKey e recuperar K

Esse é o padrão correto para usar KEMs em criptografia híbrida.

## Segurança

- ✅ **AES-GCM-256**: Criptografia autenticada com chaves de 256 bits
- ✅ **ML-KEM-768**: Resistente a computadores quânticos (nível de segurança 3 do NIST)
- ✅ **IVs únicos**: Cada operação AES-GCM usa um IV aleatório de 12 bytes
- ✅ **Sem reutilização de IV**: Garantido através de getRandomValues
- ✅ **WebCrypto nativo**: Implementação confiável e auditada

## Troubleshooting

### Warnings Experimentais

É normal ver warnings sobre funcionalidades experimentais:
```
(node:12469) ExperimentalWarning: The ML-KEM-768 Web Crypto API algorithm is an experimental feature
```

Esses warnings são informativos e não afetam o funcionamento do código.

## Estrutura do Projeto

```
TLS-with-ML-KEM/
├── mlkem_aes.ts       # Módulo principal com 5 funções exportadas
├── example.ts         # Exemplo executável completo
├── package.json       # Configuração do projeto
├── tsconfig.json      # Configuração TypeScript
├── README.md          # Documentação
└── .gitignore         # Arquivos ignorados pelo Git
```

## Licença

MIT

