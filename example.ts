/**
 * example.ts
 * 
 * Exemplo executável demonstrando o uso completo do mlkem_aes.ts
 * 
 * Para executar:
 * node --experimental-strip-types example.ts
 */

import { webcrypto } from "node:crypto";
import {
    generateK,
    encapsulateK,
    decapsulateK,
    aesEncryptText,
    aesDecryptText,
    type EncapsulatedK,
    type AesEncryptedText
} from "./mlkem_aes.ts";

async function main() {
    console.log("=".repeat(80));
    console.log("Exemplo: ML-KEM-768 + AES-GCM-256 Criptografia Híbrida");
    console.log("=".repeat(80));
    console.log();

    try {
        // ========================================================================
        // PASSO 1: Destinatário (Bob) gera par de chaves ML-KEM-768
        // ========================================================================
        console.log("📋 Passo 1: Bob gera par de chaves ML-KEM-768");
        const bobKeyPair = await webcrypto.subtle.generateKey(
            "ML-KEM-768",
            true,
            ["encapsulateKey", "decapsulateKey"]
        );
        console.log("✅ Par de chaves ML-KEM-768 gerado com sucesso");
        console.log("   - Chave pública: ", bobKeyPair.publicKey);
        console.log("   - Chave privada: ", bobKeyPair.privateKey);
        console.log("   - Chave pública: disponível para Alice");
        console.log("   - Chave privada: mantida em segredo por Bob");
        console.log();

        // ========================================================================
        // PASSO 2: Remetente (Alice) gera chave simétrica K
        // ========================================================================
        console.log("📋 Passo 2: Alice gera chave simétrica K (AES-GCM-256)");
        const K = await generateK();
        console.log("✅ Chave K gerada com sucesso");
        console.log("   - Chave K: ", K);
        console.log();

        // ========================================================================
        // PASSO 3: Alice encapsula K usando chave pública de Bob
        // ========================================================================
        console.log("📋 Passo 3: Alice encapsula K com chave pública de Bob");
        const encapsulated: EncapsulatedK = await encapsulateK(bobKeyPair.publicKey, K);
        console.log("✅ Encapsulamento concluído");
        console.log("   Dados para transmissão:");
        console.log(`   - kemCiphertextB64: ${encapsulated.kemCiphertextB64.substring(0, 50)}...`);
        console.log(`   - wrapIvB64: ${encapsulated.wrapIvB64}`);
        console.log(`   - wrappedKB64: ${encapsulated.wrappedKB64.substring(0, 50)}...`);
        console.log();

        // ========================================================================
        // PASSO 4: Bob recebe os dados e decapsula para recuperar K
        // ========================================================================
        console.log("📋 Passo 4: Bob decapsula e recupera K com sua chave privada");
        const recoveredK = await decapsulateK(bobKeyPair.privateKey, encapsulated);
        console.log("✅ Chave K recuperada com sucesso");
        console.log();

        // ========================================================================
        // PASSO 5: Alice criptografa mensagem com K
        // ========================================================================
        const mensagem = "Hello, Bob! Esta é uma mensagem secreta protegida por criptografia pós-quântica. 🔐";
        console.log("📋 Passo 5: Alice criptografa mensagem com K");
        console.log(`   Mensagem original: "${mensagem}"`);
        const encrypted: AesEncryptedText = await aesEncryptText(K, mensagem);
        console.log("✅ Mensagem criptografada");
        console.log("   Dados criptografados:");
        console.log(`   - ivB64: ${encrypted.ivB64}`);
        console.log(`   - ciphertextB64: ${encrypted.ciphertextB64.substring(0, 50)}...`);
        console.log();

        // ========================================================================
        // PASSO 6: Bob descriptografa mensagem com K recuperada
        // ========================================================================
        console.log("📋 Passo 6: Bob descriptografa mensagem com K recuperada");
        const decrypted = await aesDecryptText(recoveredK, encrypted);
        console.log("✅ Mensagem descriptografada com sucesso");
        console.log(`   Mensagem recuperada: "${decrypted}"`);
        console.log();

        // ========================================================================
        // VERIFICAÇÃO: As mensagens são idênticas
        // ========================================================================
        console.log("=".repeat(80));
        if (mensagem === decrypted) {
            console.log("✅ SUCESSO! A mensagem foi recuperada corretamente.");
            console.log("✅ K original e recoveredK são criptograficamente equivalentes.");
        } else {
            console.log("❌ ERRO! As mensagens não coincidem.");
            console.log(`   Original:  "${mensagem}"`);
            console.log(`   Recuperado: "${decrypted}"`);
        }
        console.log("=".repeat(80));
        console.log();

        // ========================================================================
        // TESTE ADICIONAL: Múltiplas mensagens
        // ========================================================================
        console.log("📋 Teste adicional: Criptografar múltiplas mensagens");
        const mensagens = [
            "Primeira mensagem",
            "Segunda mensagem",
            "Terceira mensagem com caracteres especiais: àáâãäåæçèéêë 🚀"
        ];

        for (let i = 0; i < mensagens.length; i++) {
            const msg = mensagens[i];
            const enc = await aesEncryptText(recoveredK, msg);
            const dec = await aesDecryptText(recoveredK, enc);

            if (msg === dec) {
                console.log(`   ✅ Mensagem ${i + 1}: OK`);
            } else {
                console.log(`   ❌ Mensagem ${i + 1}: FALHOU`);
            }
        }
        console.log();

        // ========================================================================
        // INFORMAÇÕES TÉCNICAS
        // ========================================================================
        console.log("=".repeat(80));
        console.log("📊 Informações Técnicas");
        console.log("=".repeat(80));
        console.log("Algoritmo de Encapsulamento: ML-KEM-768 (post-quantum)");
        console.log("Algoritmo de Criptografia: AES-GCM-256");
        console.log("Tamanho do IV: 12 bytes (96 bits)");
        console.log("Tamanho da Chave K: 32 bytes (256 bits)");
        console.log("Nível de Segurança: NIST Level 3");
        console.log("Node.js Version Mínima: 24.7.0");
        console.log("=".repeat(80));

    } catch (error) {
        console.error("❌ Erro durante execução:");
        console.error(error);
        process.exit(1);
    }
}

// Executar exemplo
main();

