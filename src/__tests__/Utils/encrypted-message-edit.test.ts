import { randomBytes } from 'crypto'
import { EventEmitter } from 'events'
import { jest } from '@jest/globals'
import { proto } from '../../../WAProto/index.js'
import type { AuthenticationCreds, BaileysEventEmitter, WAMessage } from '../../Types'
import { aesEncryptGCM, hmacSign } from '../../Utils/crypto'
import processMessage, { isRealMessage, unwrapSecretEncryptedMessage } from '../../Utils/process-message'

const messageId = 'ORIGINAL_TEST_ID'
const chat = 'test-user@lid'
const messageSecret = randomBytes(32)

const seal = (inner: proto.IMessage, id = messageId, jid = chat, secret = messageSecret) => {
	const info = Buffer.concat([
		Buffer.from(id),
		Buffer.from(jid),
		Buffer.from(jid),
		Buffer.from('Message Edit'),
		new Uint8Array([1])
	])
	const key0 = hmacSign(secret, new Uint8Array(32), 'sha256')
	const key = hmacSign(info, key0, 'sha256')
	const iv = randomBytes(12)
	const encPayload = aesEncryptGCM(
		proto.Message.encode(proto.Message.fromObject(inner)).finish(),
		key,
		iv,
		new Uint8Array(0)
	)
	return { encPayload, encIv: iv }
}

const editInner = (text: string): proto.IMessage => ({
	conversation: text
})

const envelope = (
	sealed: { encPayload: Uint8Array; encIv: Uint8Array },
	changes: Partial<WAMessage['key']> = {},
	targetChanges: Partial<WAMessage['key']> = {}
): WAMessage => ({
	key: { remoteJid: chat, fromMe: false, id: 'ENVELOPE_TEST_ID', ...changes },
	message: {
		secretEncryptedMessage: {
			targetMessageKey: { remoteJid: chat, fromMe: false, id: messageId, ...targetChanges },
			secretEncType: proto.Message.SecretEncryptedMessage.SecretEncType.MESSAGE_EDIT,
			encPayload: sealed.encPayload,
			encIv: sealed.encIv
		}
	},
	messageTimestamp: 1_793_300_000
})

const original = (
	keyChanges: Partial<WAMessage['key']> = {},
	secret: Uint8Array | undefined = messageSecret
): WAMessage => ({
	key: { remoteJid: chat, fromMe: false, id: messageId, ...keyChanges },
	message: { conversation: 'original', messageContextInfo: { messageSecret: secret } }
})

const makeEmitter = () => new EventEmitter() as unknown as BaileysEventEmitter

const process = async (message: WAMessage, ev: BaileysEventEmitter, logger?: any, isSecretEdit = false) =>
	processMessage(message, {
		shouldProcessHistoryMsg: false,
		isSecretEdit,
		ev,
		logger,
		creds: { me: { id: 'self@s.whatsapp.net' } } as AuthenticationCreds,
		signalRepository: {} as never,
		keyStore: {} as never,
		options: {},
		getMessage: async () => undefined
	})

describe('encrypted message edits', () => {
	it('unwraps to the existing messages.update shape with the original identity', async () => {
		const msg = envelope(seal(editInner('edited')))
		expect(isRealMessage(msg)).toBe(false)
		const getMessageForEdit = jest.fn(async () => original())
		const diagnostics: unknown[] = []
		const logger = { info: (record: unknown) => diagnostics.push(record) } as any
		await unwrapSecretEncryptedMessage(msg, {
			creds: { me: { id: 'self@s.whatsapp.net' } } as AuthenticationCreds,
			getMessageForEdit,
			logger
		})
		const ev = makeEmitter()
		const updates: any[] = []
		ev.on('messages.update', value => updates.push(value))
		await process(msg, ev, logger, true)
		expect(getMessageForEdit).toHaveBeenCalledWith({ remoteJid: chat, fromMe: false, id: messageId })
		expect(updates).toHaveLength(1)
		expect(updates[0][0].key).toMatchObject({ remoteJid: chat, fromMe: false, id: messageId })
		expect(updates[0][0].update.message.editedMessage.message.conversation).toBe('edited')
		expect(diagnostics.map((entry: any) => entry.stage)).toEqual([
			'encrypted_envelope_received',
			'original_lookup',
			'original_secret',
			'decryption_result',
			'messages_update_emission'
		])
		expect((diagnostics.at(-1) as any).source).toBe('encrypted')
		const diagnosticText = JSON.stringify(diagnostics)
		expect(diagnosticText).not.toContain(messageId)
		expect(diagnosticText).not.toContain(chat)
		expect(diagnosticText).not.toContain('edited')
	})

	it('uses the paired self LID from authenticated credentials for self-authored group edits', async () => {
		const group = 'test-group@g.us'
		const selfLid = 'self@lid'
		const msg = envelope(
			seal(editInner('self edit'), messageId, selfLid),
			{ remoteJid: group, fromMe: true, participant: selfLid },
			{ remoteJid: group, fromMe: true, participant: selfLid }
		)
		const stored = original({ remoteJid: group, fromMe: true, participant: selfLid })
		const credentials = { me: { id: 'self@s.whatsapp.net', lid: selfLid } } as AuthenticationCreds
		await unwrapSecretEncryptedMessage(msg, { creds: credentials, getMessageForEdit: async () => stored })
		expect(msg.message?.protocolMessage?.editedMessage?.conversation).toBe('self edit')
	})

	it('uses a phone/LID alternate only when the exact pair is on both event and stored keys', async () => {
		const pn = 'test-user@s.whatsapp.net'
		const msg = envelope(seal(editInner('mapped edit'), messageId, pn), { remoteJidAlt: pn }, { remoteJidAlt: pn })
		const stored = original({ remoteJidAlt: pn })
		await unwrapSecretEncryptedMessage(msg, {
			creds: { me: { id: 'self@s.whatsapp.net' } } as AuthenticationCreds,
			getMessageForEdit: async () => stored
		})
		expect(msg.message?.protocolMessage?.editedMessage?.conversation).toBe('mapped edit')
	})

	it('accepts the stored base64 message secret representation', async () => {
		const msg = envelope(seal(editInner('edited')))
		const stored = original()
		stored.message!.messageContextInfo!.messageSecret = messageSecret.toString('base64') as unknown as Uint8Array
		await unwrapSecretEncryptedMessage(msg, {
			creds: { me: { id: 'self@s.whatsapp.net' } } as AuthenticationCreds,
			getMessageForEdit: async () => stored
		})
		expect(msg.message?.protocolMessage?.editedMessage?.conversation).toBe('edited')
	})

	it('keeps traditional protocol edits working', async () => {
		const msg: WAMessage = {
			key: { remoteJid: chat, fromMe: false, id: 'legacy-envelope' },
			message: {
				protocolMessage: {
					key: { remoteJid: chat, fromMe: false, id: messageId },
					type: proto.Message.ProtocolMessage.Type.MESSAGE_EDIT,
					editedMessage: { conversation: 'legacy edit' }
				}
			}
		}
		const ev = makeEmitter()
		const updates: any[] = []
		ev.on('messages.update', value => updates.push(value))
		await process(msg, ev)
		expect(updates[0][0].update.message.editedMessage.message.conversation).toBe('legacy edit')
	})

	it('fails closed without the exact original, key, or message secret', async () => {
		const credentials = { me: { id: 'self@s.whatsapp.net' } } as AuthenticationCreds
		for (const getMessageForEdit of [
			async () => undefined,
			async () => original({ remoteJid: 'other-user@lid' }),
			async () => original({}, undefined)
		]) {
			const msg = envelope(seal(editInner('edited')))
			await unwrapSecretEncryptedMessage(msg, { creds: credentials, getMessageForEdit })
			expect(msg.message?.secretEncryptedMessage).toBeDefined()
		}
	})

	it('does not query or mutate when the target ID is missing', async () => {
		const msg = envelope(seal(editInner('edited')))
		delete msg.message!.secretEncryptedMessage!.targetMessageKey!.id
		const getMessageForEdit = jest.fn(async () => original())
		await unwrapSecretEncryptedMessage(msg, {
			creds: { me: { id: 'self@s.whatsapp.net' } } as AuthenticationCreds,
			getMessageForEdit
		})
		expect(getMessageForEdit).not.toHaveBeenCalled()
		expect(msg.message?.secretEncryptedMessage).toBeDefined()
	})

	it('rejects invalid ciphertext and does not fall back across LID/phone namespaces', async () => {
		const credentials = { me: { id: 'self@s.whatsapp.net' } } as AuthenticationCreds
		const badCiphertext = envelope({
			encPayload: new Uint8Array(randomBytes(30)),
			encIv: new Uint8Array(randomBytes(12))
		})
		await unwrapSecretEncryptedMessage(badCiphertext, { creds: credentials, getMessageForEdit: async () => original() })
		expect(badCiphertext.message?.secretEncryptedMessage).toBeDefined()

		const pnKey = 'test-user@s.whatsapp.net'
		const wrongNamespace = envelope(seal(editInner('edited')), { remoteJid: pnKey }, { remoteJid: pnKey })
		await unwrapSecretEncryptedMessage(wrongNamespace, {
			creds: credentials,
			getMessageForEdit: async () => original({ remoteJid: pnKey })
		})
		expect(wrongNamespace.message?.secretEncryptedMessage).toBeDefined()
	})

	it('handles duplicate delivery deterministically for downstream idempotency', async () => {
		const updates: any[] = []
		const ev = makeEmitter()
		ev.on('messages.update', value => updates.push(value))
		for (let i = 0; i < 2; i++) {
			const msg = envelope(seal(editInner('same edit')))
			await unwrapSecretEncryptedMessage(msg, {
				creds: { me: { id: 'self@s.whatsapp.net' } } as AuthenticationCreds,
				getMessageForEdit: async () => original()
			})
			await process(msg, ev)
		}
		expect(updates).toHaveLength(2)
		expect(updates[0]).toEqual(updates[1])
	})
})
