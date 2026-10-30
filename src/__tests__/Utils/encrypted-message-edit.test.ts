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
	targetChanges: Partial<proto.IMessageKey> = {}
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
		const logger = { info: jest.fn() } as any
		const output = jest.spyOn(console, 'info').mockImplementation(() => {})
		const diagnostics: any[] = []
		try {
			await unwrapSecretEncryptedMessage(msg, {
				creds: { me: { id: 'self@s.whatsapp.net' } } as AuthenticationCreds,
				getMessageForEdit,
				logger
			})
			const ev = makeEmitter()
			const updates: any[] = []
			ev.on('messages.update', value => updates.push(value))
			await process(msg, ev, logger, true)
			diagnostics.push(...output.mock.calls.map(([record]) => record))
			expect(getMessageForEdit).toHaveBeenCalledWith({ ...msg.key, id: messageId })
			expect(updates).toHaveLength(1)
			expect(updates[0][0].key).toEqual(original().key)
			expect(updates[0][0].update.message.editedMessage.message.conversation).toBe('edited')
			expect(updates[0][0].update.messageTimestamp).toBe(msg.messageTimestamp)
			expect(msg.messageTimestamp).toBe(1_793_300_000)
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
			expect(diagnosticText).not.toContain('ENVELOPE_TEST_ID')
			expect(diagnosticText).not.toContain(chat)
			expect(diagnosticText).not.toContain('edited')
			expect(diagnosticText).not.toContain(messageSecret.toString('base64'))
			expect(diagnosticText).not.toContain('self@s.whatsapp.net')
			expect(logger.info).not.toHaveBeenCalled()
		} finally {
			output.mockRestore()
		}
	})

	it('does not emit an envelope diagnostic for ordinary messages', async () => {
		const output = jest.spyOn(console, 'info').mockImplementation(() => {})
		try {
			const ordinary: WAMessage = { key: { remoteJid: chat, fromMe: false }, message: { conversation: 'ordinary' } }
			expect(
				await unwrapSecretEncryptedMessage(ordinary, {
					creds: { me: { id: 'self@s.whatsapp.net' } } as AuthenticationCreds
				})
			).toBe(false)
			expect(output).not.toHaveBeenCalled()
		} finally {
			output.mockRestore()
		}
	})

	it('finds an encrypted edit inside a supported content wrapper', async () => {
		const msg = envelope(seal(editInner('wrapped edit')))
		msg.message = { ephemeralMessage: { message: msg.message! } }
		const getMessageForEdit = jest.fn(async () => original())
		const output = jest.spyOn(console, 'info').mockImplementation(() => {})
		try {
			expect(
				await unwrapSecretEncryptedMessage(msg, {
					creds: { me: { id: 'self@s.whatsapp.net' } } as AuthenticationCreds,
					getMessageForEdit
				})
			).toBe(true)
			expect(getMessageForEdit).toHaveBeenCalledTimes(1)
			expect(msg.message?.protocolMessage?.editedMessage?.conversation).toBe('wrapped edit')
			expect(output.mock.calls[0]![0]).toMatchObject({
				diagnostic: 'whatsapp_edit',
				stage: 'encrypted_envelope_received',
				envelope_type: 'message_edit'
			})
		} finally {
			output.mockRestore()
		}
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

	it('matches a direct protobuf key when the receive key has an alternate JID', async () => {
		const pn = 'test-user@s.whatsapp.net'
		const msg = envelope(seal(editInner('mapped edit')), { remoteJidAlt: pn })
		const stored = original({ remoteJidAlt: pn })
		const getMessageForEdit = jest.fn(async () => stored)
		const output = jest.spyOn(console, 'info').mockImplementation(() => {})
		try {
			await unwrapSecretEncryptedMessage(msg, {
				creds: { me: { id: 'self@s.whatsapp.net' } } as AuthenticationCreds,
				getMessageForEdit
			})
			expect(getMessageForEdit).toHaveBeenCalledWith({ ...msg.key, id: messageId })
			expect(msg.message?.protocolMessage?.editedMessage?.conversation).toBe('mapped edit')
			const lookup = output.mock.calls.map(([record]) => record as any).find(record => record.result === 'matched')
			expect(lookup).toMatchObject({
				target_from_me_differs_from_envelope: false,
				target_remote_jid_differs_from_envelope: false,
				target_participant_differs_from_envelope: false
			})
			const diagnosticText = JSON.stringify(output.mock.calls)
			for (const privateValue of [
				messageId,
				'ENVELOPE_TEST_ID',
				chat,
				pn,
				'mapped edit',
				messageSecret.toString('base64'),
				'self@s.whatsapp.net'
			]) {
				expect(diagnosticText).not.toContain(privateValue)
			}
		} finally {
			output.mockRestore()
		}
	})

	it('matches an incoming direct PN/LID key only through reciprocal received alternates', async () => {
		const pn = 'test-user@s.whatsapp.net'
		const lid = 'test-user@lid'
		const msg = envelope(
			seal(editInner('reciprocal direct edit'), messageId, lid),
			{ remoteJid: pn, remoteJidAlt: lid },
			{ remoteJid: 'self@lid', fromMe: true }
		)
		const stored = original({ remoteJid: lid, remoteJidAlt: pn })
		const result = await unwrapSecretEncryptedMessage(msg, {
			creds: { me: { id: 'self@s.whatsapp.net' } } as AuthenticationCreds,
			getMessageForEdit: async () => stored
		})
		expect(result).toBe(true)
		expect(msg.key).toEqual(stored.key)
		expect(msg.message?.protocolMessage?.editedMessage?.conversation).toBe('reciprocal direct edit')
	})

	it('matches a group protobuf key when the receive key has a participant alternate', async () => {
		const group = 'test-group@g.us'
		const participant = 'test-author@lid'
		const pn = 'test-author@s.whatsapp.net'
		const msg = envelope(
			seal(editInner('group edit'), messageId, participant),
			{ remoteJid: group, participant: pn, participantAlt: participant },
			{ remoteJid: group, fromMe: true, participant }
		)
		const stored = original({ remoteJid: group, participant, participantAlt: pn })
		const output = jest.spyOn(console, 'info').mockImplementation(() => {})
		try {
			await unwrapSecretEncryptedMessage(msg, {
				creds: { me: { id: 'self@s.whatsapp.net' } } as AuthenticationCreds,
				getMessageForEdit: async () => stored
			})
			expect(msg.message?.protocolMessage?.editedMessage?.conversation).toBe('group edit')
			const lookup = output.mock.calls.map(([record]) => record as any).find(record => record.result === 'matched')
			expect(lookup).toMatchObject({
				target_from_me_differs_from_envelope: true,
				target_remote_jid_differs_from_envelope: false,
				target_participant_differs_from_envelope: true
			})
			const diagnosticText = JSON.stringify(output.mock.calls)
			for (const privateValue of [
				messageId,
				'ENVELOPE_TEST_ID',
				group,
				participant,
				pn,
				'group edit',
				messageSecret.toString('base64'),
				'self@s.whatsapp.net'
			]) {
				expect(diagnosticText).not.toContain(privateValue)
			}
		} finally {
			output.mockRestore()
		}
	})

	const targetPerspectiveCases: Array<{
		name: string
		messageKey?: Partial<WAMessage['key']>
		targetKey: Partial<proto.IMessageKey>
		expected: Record<string, boolean>
	}> = [
		{
			name: 'fromMe and remoteJid',
			targetKey: { fromMe: true, remoteJid: 'self@lid' },
			expected: {
				target_from_me_differs_from_envelope: true,
				target_remote_jid_differs_from_envelope: true,
				target_participant_differs_from_envelope: false
			}
		},
		{
			name: 'participant',
			messageKey: {
				remoteJid: 'test-group@g.us',
				participant: 'test-author@lid',
				participantAlt: 'test-author@s.whatsapp.net'
			},
			targetKey: { remoteJid: 'test-group@g.us', fromMe: true, participant: 'other-author@lid' },
			expected: {
				target_from_me_differs_from_envelope: true,
				target_remote_jid_differs_from_envelope: false,
				target_participant_differs_from_envelope: true
			}
		}
	]

	it.each(targetPerspectiveCases)(
		'accepts sender-perspective target $name differences using the received identity',
		async ({ messageKey = {}, targetKey, expected }) => {
			const authorJid = messageKey.participant || chat
			const msg = envelope(seal(editInner('private edit body'), messageId, authorJid), messageKey, targetKey)
			const stored = original(messageKey)
			const getMessageForEdit = jest.fn(async () => stored)
			const output = jest.spyOn(console, 'info').mockImplementation(() => {})
			try {
				expect(
					await unwrapSecretEncryptedMessage(msg, {
						creds: { me: { id: 'self@s.whatsapp.net' } } as AuthenticationCreds,
						getMessageForEdit
					})
				).toBe(true)
				expect(getMessageForEdit).toHaveBeenCalledWith({ ...msg.key, id: messageId })
				const diagnostic = output.mock.calls
					.map(([record]) => record as any)
					.find(record => record.result === 'matched')
				expect(diagnostic).toMatchObject({ diagnostic: 'whatsapp_edit', stage: 'original_lookup', ...expected })
				expect(msg.key).toEqual(stored.key)
				const diagnosticText = JSON.stringify(output.mock.calls)
				for (const privateValue of [
					messageId,
					'ENVELOPE_TEST_ID',
					chat,
					'self@lid',
					'other-author@lid',
					'test-group@g.us',
					'test-author@lid',
					'private edit body',
					messageSecret.toString('base64'),
					'self@s.whatsapp.net'
				]) {
					expect(diagnosticText).not.toContain(privateValue)
				}
			} finally {
				output.mockRestore()
			}
		}
	)

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
			async () => original({ id: 'OTHER_ORIGINAL_ID' }),
			async () => original({ fromMe: true }),
			async () => original({ remoteJid: 'other-user@lid' }),
			async () => original({ participant: 'other-participant@lid' }),
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
