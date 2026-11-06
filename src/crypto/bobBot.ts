import {
  decryptEndpointMessage,
  encryptEndpointMessage,
  type EncryptedEnvelope,
  type EndpointSessionState,
} from './arxCrypto.ts';

export interface BotProcessResult {
  inboundDecrypt: Awaited<ReturnType<typeof decryptEndpointMessage>>;
  botReplyPlaintext?: string;
  outboundEncrypt?: Awaited<ReturnType<typeof encryptEndpointMessage>>;
  updatedBobState: EndpointSessionState;
}

/**
 * Pure rule-based command parser for the local Bob Bot endpoint.
 * Supported commands:
 * - hello
 * - time
 * - help
 * - echo <text>
 */
export function evaluateBobBotCommand(plaintext: string): string {
  const trimmed = plaintext.trim();
  const lower = trimmed.toLowerCase();

  if (lower === 'hello' || lower === 'hi') {
    return 'Hello from Bob Endpoint Bot! Session integrity verified via AES-256-GCM. Try "help", "time", or "echo <text>".';
  }

  if (lower === 'time') {
    return `Bob Local Endpoint Clock: ${new Date().toISOString()} (UTC)`;
  }

  if (lower === 'help') {
    return 'Bob Bot Endpoint Commands: "hello" (greeting), "time" (current UTC timestamp), "help" (list commands), "echo <text>" (echoes back your verified payload).';
  }

  if (lower.startsWith('echo ')) {
    const payload = trimmed.slice(5);
    return `[Bob Bot Echo]: ${payload}`;
  }

  if (lower === 'echo') {
    return '[Bob Bot Echo]: (empty payload — usage: echo <text>)';
  }

  return `Bob Bot received verified message (${trimmed.length} chars). Type "help" for bot commands ("hello", "time", "help", "echo <text>").`;
}

/**
 * Processes an incoming EncryptedEnvelope at the local Bob Bot endpoint:
 * 1. Authenticates and decrypts the envelope using Bob's local receiving ratchet chain.
 * 2. If valid, generates a rule-based response.
 * 3. Encrypts the response using Bob's local sending ratchet chain so the relay only ever sees ciphertext.
 */
export async function processEnvelopeAtBobBotEndpoint(
  bobState: EndpointSessionState,
  incomingEnvelope: EncryptedEnvelope,
  options?: { allowLocalPlaintextDemo?: boolean }
): Promise<BotProcessResult> {
  const inboundDecrypt = await decryptEndpointMessage(bobState, incomingEnvelope, options);

  if (!inboundDecrypt.success || inboundDecrypt.plaintext === undefined) {
    return {
      inboundDecrypt,
      updatedBobState: inboundDecrypt.updatedState,
    };
  }

  const botReplyPlaintext = evaluateBobBotCommand(inboundDecrypt.plaintext);
  const outboundEncrypt = await encryptEndpointMessage(
    inboundDecrypt.updatedState,
    botReplyPlaintext,
    options
  );

  return {
    inboundDecrypt,
    botReplyPlaintext,
    outboundEncrypt,
    updatedBobState: outboundEncrypt.updatedState,
  };
}
