/**
 * mlkem_aes.ts
 * 
 * Implementação de criptografia híbrida usando ML-KEM-768 + AES-GCM-256
 * para Node.js >= 24.7.0 usando apenas WebCrypto (sem libs externas).
 * 
 * NOTA CRIPTOGRÁFICA:
 * ML-KEM é um KEM (Key Encapsulation Mechanism), não um algoritmo de cifra.
 * Portanto, não podemos cifrar diretamente uma chave K escolhida.
 * 
 * O fluxo de encapsulamento funciona assim:
 * 1. encapsulateKey gera uma wrappingKey aleatória + kemCiphertext
 * 2. Exportamos K como raw bytes
 * 3. Ciframos esses bytes com wrappingKey via AES-GCM
 * 4. Retornamos kemCiphertext + wrappedK + wrapIv
 * 
 * No decapsulamento:
 * 1. decapsulateKey recupera a mesma wrappingKey usando kemCiphertext
 * 2. Deciframos wrappedK com wrappingKey
 * 3. Importamos os bytes recuperados como CryptoKey AES-GCM
 */

import { webcrypto } from "node:crypto";

// ============================================================================
// HELPERS (internos)
// ============================================================================

/**
 * Converte ArrayBuffer para string base64
 */
function abToB64(ab: ArrayBuffer): string {
    return Buffer.from(ab).toString("base64");
}

/**
 * Converte string base64 para Uint8Array
 */
function b64ToU8(b64: string): Uint8Array {
    return new Uint8Array(Buffer.from(b64, "base64"));
}

// ============================================================================
// TIPOS EXPORTADOS
// ============================================================================

/**
 * Dados retornados pelo encapsulamento da chave K
 */
export type EncapsulatedK = {
    kemCiphertextB64: string; // ciphertext do ML-KEM
    wrapIvB64: string;        // IV do AES-GCM usado para cifrar a K
    wrappedKB64: string;      // K exportada (raw) cifrada com AES-GCM
};

/**
 * Dados retornados pela criptografia de texto com AES-GCM
 */
export type AesEncryptedText = {
    ivB64: string;           // IV do AES-GCM do payload
    ciphertextB64: string;   // ciphertext do payload (inclui tag GCM)
};

// ============================================================================
// FUNÇÕES EXPORTADAS
// ============================================================================

/**
 * 1) Gera uma chave simétrica K para AES-GCM-256
 * 
 * A chave é gerada como extractable=true para permitir exportKey
 * no processo de encapsulamento.
 */
export async function generateK(): Promise<CryptoKey> {
    try {
        return await webcrypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256,
            },
            true, // extractable=true (necessário para exportKey no encapsulateK)
            ["encrypt", "decrypt"]
        );
    } catch (error) {
        throw new Error(`Erro ao gerar chave K: ${error instanceof Error ? error.message : String(error)}`);
    }
}

/**
 * 2) Encapsula a chave K usando ML-KEM-768
 * 
 * Fluxo:
 * - Chama subtle.encapsulateKey para gerar wrappingKey + kemCiphertext
 * - Exporta K como raw bytes
 * - Cifra os bytes de K com wrappingKey via AES-GCM (usando IV aleatório)
 * - Retorna kemCiphertext, wrapIv e wrappedK em base64
 * 
 * @param recipientPublicKey - Chave pública ML-KEM-768 do destinatário
 * @param K - Chave simétrica AES-GCM a ser encapsulada
 */
export async function encapsulateK(
    recipientPublicKey: CryptoKey,
    K: CryptoKey
): Promise<EncapsulatedK> {
    try {
        // Passo 1: Gerar wrappingKey usando ML-KEM-768
        const encapResult = await webcrypto.subtle.encapsulateKey(
            "ML-KEM-768",
            recipientPublicKey,
            {
                name: "AES-GCM",
                length: 256,
            },
            false, // wrappingKey não precisa ser extractable
            ["encrypt"]
        );

        const kemCiphertext = encapResult.ciphertext;
        const wrappingKey = encapResult.sharedKey;

        // Passo 2: Exportar K como raw bytes
        const kRaw = await webcrypto.subtle.exportKey("raw", K);

        // Passo 3: Gerar IV aleatório de 12 bytes para cifrar K
        const wrapIv = webcrypto.getRandomValues(new Uint8Array(12));

        // Passo 4: Cifrar kRaw com wrappingKey usando AES-GCM
        const wrappedK = await webcrypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: wrapIv,
            },
            wrappingKey,
            kRaw
        );

        // Retornar tudo em base64
        return {
            kemCiphertextB64: abToB64(kemCiphertext),
            wrapIvB64: abToB64(wrapIv),
            wrappedKB64: abToB64(wrappedK),
        };
    } catch (error) {
        throw new Error(`Erro ao encapsular chave K: ${error instanceof Error ? error.message : String(error)}`);
    }
}

/**
 * 3) Decapsula a chave K usando ML-KEM-768
 * 
 * Fluxo:
 * - Chama subtle.decapsulateKey para derivar a mesma wrappingKey
 * - Decifra wrappedK usando wrappingKey + wrapIv
 * - Importa os bytes recuperados como CryptoKey AES-GCM
 * 
 * @param recipientPrivateKey - Chave privada ML-KEM-768 do destinatário
 * @param data - Dados do encapsulamento (kemCiphertext, wrapIv, wrappedK)
 */
export async function decapsulateK(
    recipientPrivateKey: CryptoKey,
    data: EncapsulatedK
): Promise<CryptoKey> {
    try {
        // Converter base64 para bytes
        const kemCiphertext = b64ToU8(data.kemCiphertextB64);
        const wrapIv = b64ToU8(data.wrapIvB64);
        const wrappedK = b64ToU8(data.wrappedKB64);

        // Passo 1: Derivar a mesma wrappingKey usando ML-KEM-768
        const wrappingKey = await webcrypto.subtle.decapsulateKey(
            "ML-KEM-768",
            recipientPrivateKey,
            kemCiphertext,
            {
                name: "AES-GCM",
                length: 256,
            },
            false, // wrappingKey não precisa ser extractable
            ["decrypt"]
        );

        // Passo 2: Decifrar wrappedK usando wrappingKey
        const kRawBytes = await webcrypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: wrapIv,
            },
            wrappingKey,
            wrappedK
        );

        // Passo 3: Importar os bytes recuperados como CryptoKey AES-GCM
        const K = await webcrypto.subtle.importKey(
            "raw",
            kRawBytes,
            {
                name: "AES-GCM",
                length: 256,
            },
            true, // extractable=true (para permitir futuro encapsulamento)
            ["encrypt", "decrypt"]
        );

        return K;
    } catch (error) {
        throw new Error(`Erro ao decapsular chave K: ${error instanceof Error ? error.message : String(error)}`);
    }
}

/**
 * 4) Criptografa texto usando AES-GCM com a chave K
 * 
 * - Converte texto para bytes usando TextEncoder
 * - Gera IV aleatório de 12 bytes (nunca reutilizar IV com mesma chave)
 * - Cifra com AES-GCM
 * - Retorna IV e ciphertext em base64
 * 
 * @param K - Chave simétrica AES-GCM
 * @param plaintext - Texto a ser criptografado
 */
export async function aesEncryptText(
    K: CryptoKey,
    plaintext: string
): Promise<AesEncryptedText> {
    try {
        // Converter texto para bytes
        const encoder = new TextEncoder();
        const plaintextBytes = encoder.encode(plaintext);

        // Gerar IV aleatório de 12 bytes (96 bits) para AES-GCM
        // IMPORTANTE: Nunca reutilizar IV com a mesma chave!
        const iv = webcrypto.getRandomValues(new Uint8Array(12));

        // Cifrar com AES-GCM
        const ciphertext = await webcrypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv,
            },
            K,
            plaintextBytes
        );

        return {
            ivB64: abToB64(iv),
            ciphertextB64: abToB64(ciphertext),
        };
    } catch (error) {
        throw new Error(`Erro ao criptografar texto: ${error instanceof Error ? error.message : String(error)}`);
    }
}

/**
 * 5) Descriptografa texto usando AES-GCM com a chave K
 * 
 * - Decifra o ciphertext usando K e IV fornecido
 * - Converte bytes para texto usando TextDecoder
 * - Retorna o texto original
 * 
 * @param K - Chave simétrica AES-GCM
 * @param data - Dados criptografados (IV e ciphertext)
 */
export async function aesDecryptText(
    K: CryptoKey,
    data: AesEncryptedText
): Promise<string> {
    try {
        // Converter base64 para bytes
        const iv = b64ToU8(data.ivB64);
        const ciphertext = b64ToU8(data.ciphertextB64);

        // Decifrar com AES-GCM
        const plaintextBytes = await webcrypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv,
            },
            K,
            ciphertext
        );

        // Converter bytes para texto
        const decoder = new TextDecoder();
        return decoder.decode(plaintextBytes);
    } catch (error) {
        throw new Error(`Erro ao descriptografar texto: ${error instanceof Error ? error.message : String(error)}`);
    }
}

// ============================================================================
// EXEMPLO DE USO (comentado)
// ============================================================================

/*

EXEMPLO DE FLUXO COMPLETO:

// 1. Destinatário (Bob) gera par de chaves ML-KEM-768
const bobKeyPair = await webcrypto.subtle.generateKey(
  "ML-KEM-768",
  true,
  ["encapsulateKey", "decapsulateKey"]
);

// 2. Remetente (Alice) gera chave simétrica K
const K = await generateK();

// 3. Alice encapsula K usando chave pública de Bob
const encapsulated = await encapsulateK(bobKeyPair.publicKey, K);

// 4. Alice envia encapsulated para Bob (kemCiphertextB64, wrapIvB64, wrappedKB64)
// Esses dados podem ser transmitidos pela rede

// 5. Bob decapsula e recupera K usando sua chave privada
const recoveredK = await decapsulateK(bobKeyPair.privateKey, encapsulated);

// 6. Alice criptografa mensagem com K
const encrypted = await aesEncryptText(K, "Hello, Bob! This is a secret message.");

// 7. Alice envia encrypted para Bob (ivB64, ciphertextB64)

// 8. Bob descriptografa mensagem com a K recuperada
const decrypted = await aesDecryptText(recoveredK, encrypted);

console.log(decrypted); // "Hello, Bob! This is a secret message."

// Verificação: K original e recoveredK são criptograficamente equivalentes
// (ambos podem cifrar/decifrar as mesmas mensagens)

*/

