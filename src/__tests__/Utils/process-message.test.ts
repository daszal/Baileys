import type { WAMessage } from '../../Types'
import { proto } from '../../../WAProto/index.js'
import { cleanMessage } from '../../Utils/process-message'
import processMessage from '../../Utils/process-message'
import { makeEventBuffer } from '../../Utils/event-buffer'

const createBaseMessage = (key: Partial<WAMessage['key']>, message?: Partial<WAMessage['message']>): WAMessage => {
	return {
		key: {
			remoteJid: 'chat@s.whatsapp.net',
			fromMe: false,
			id: 'ABC',
			...key
		},
		message: message || { conversation: 'hello' },
		messageTimestamp: 1675888000
	}
}

describe('cleanMessage', () => {
	const meId = 'me@s.whatsapp.net'
	const meLid = 'me@lid'
	const otherUserId = 'other@s.whatsapp.net'

	describe('JID Normalization', () => {
		it('should correctly normalize a standard phone number JID with a device', () => {
			const message = createBaseMessage({
				remoteJid: '1234567890:15@s.whatsapp.net',
				participant: '9876543210:5@s.whatsapp.net'
			})

			cleanMessage(message, meId, meLid)

			expect(message.key.remoteJid).toBe('1234567890@s.whatsapp.net')
			expect(message.key.participant).toBe('9876543210@s.whatsapp.net')
		})

		it('should not modify a group JID', () => {
			const message = createBaseMessage({
				remoteJid: '123456-7890@g.us'
			})

			cleanMessage(message, meId, meLid)

			expect(message.key.remoteJid).toBe('123456-7890@g.us')
		})

		it('should correctly normalize a LID with a device', () => {
			const message = createBaseMessage({
				participant: '1234567890:12@lid'
			})

			cleanMessage(message, meId, meLid)

			expect(message.key.participant).toBe('1234567890@lid')
		})
	})

	describe('Hosted JID Handling', () => {
		it('should correctly normalize a hosted PN JID back to PN form', () => {
			const hostedJid = '1234567890:99@hosted'
			const message = createBaseMessage({
				remoteJid: hostedJid
			})

			cleanMessage(message, meId, meLid)

			expect(message.key.remoteJid).toBe('1234567890@s.whatsapp.net')
		})

		it('should correctly normalize a hosted LID JID back to LID form', () => {
			const hostedLidJid = '9876543210:99@hosted.lid'
			const message = createBaseMessage({
				participant: hostedLidJid
			})

			cleanMessage(message, meId, meLid)

			expect(message.key.participant).toBe('9876543210@lid')
		})
	})

	describe('Reaction Message Perspective', () => {
		it("should correct the perspective of a reaction to another user's message", () => {
			const message = createBaseMessage(
				{ fromMe: false, participant: otherUserId },
				{
					reactionMessage: {
						key: {
							remoteJid: 'chat@s.whatsapp.net',
							fromMe: false,
							id: 'MSG_THEY_SENT',
							participant: otherUserId
						},
						text: '😂'
					}
				}
			)

			cleanMessage(message, meId, meLid)

			const reactionKey = message.message!.reactionMessage!.key!
			expect(reactionKey.fromMe).toBe(false)
		})

		it('should not modify a reaction on a message I sent from another device', () => {
			const message = createBaseMessage(
				{ fromMe: true },
				{
					reactionMessage: {
						key: { remoteJid: 'chat@s.whatsapp.net', fromMe: true, id: 'MSG_I_SENT' },
						text: '❤️'
					}
				}
			)

			const originalReactionKey = { ...message.message!.reactionMessage!.key! }

			cleanMessage(message, meId, meLid)

			const reactionKey = message.message!.reactionMessage!.key!
			expect(reactionKey).toEqual(originalReactionKey)
		})
	})

	describe('Edge Cases', () => {
		it('should not crash if JIDs are undefined', () => {
			const message = createBaseMessage({
				remoteJid: undefined,
				participant: undefined
			})

			expect(() => cleanMessage(message, meId, meLid)).not.toThrow()
		})

		it('should not crash on an empty message object', () => {
			const message = createBaseMessage({}, {})
			expect(() => cleanMessage(message, meId, meLid)).not.toThrow()
		})
	})
})

describe('message revocation events', () => {
	it('carries the protocol target key without logging identifiers or message content', async () => {
		const receivedKey = { remoteJid: 'peer@s.whatsapp.net', fromMe: false, id: 'synthetic-notification-id' }
		const targetKey = { remoteJid: 'self@s.whatsapp.net', fromMe: true, id: 'synthetic-target-id' }
		const message: WAMessage = {
			key: receivedKey,
			message: {
				protocolMessage: {
					type: proto.Message.ProtocolMessage.Type.REVOKE,
					key: targetKey
				}
			},
			messageTimestamp: 1_793_300_000
		}
		const emitted: Array<{ event: string; data: any }> = []
		const log = jest.spyOn(console, 'info').mockImplementation(() => {})
		try {
			await processMessage(message, {
				shouldProcessHistoryMsg: false,
				creds: { me: { id: 'self@s.whatsapp.net' } } as any,
				keyStore: {} as any,
				ev: { emit: (event: string, data: any) => emitted.push({ event, data }) } as any,
				signalRepository: {} as any,
				options: {},
				getMessage: async () => undefined
			} as any)
		} finally {
			log.mockRestore()
		}

		expect(emitted).toHaveLength(1)
		expect(emitted[0].event).toBe('messages.update')
		expect(emitted[0].data[0].key).toEqual({ ...receivedKey, id: targetKey.id })
		expect(emitted[0].data[0].revokeTargetKey).toEqual(targetKey)
		expect(emitted[0].data[0].update.message).toBeNull()
		expect(emitted[0].data[0].update.messageStubType).toBe(proto.WebMessageInfo.StubType.REVOKE)
		const diagnosticOutput = JSON.stringify(log.mock.calls)
		expect(diagnosticOutput).not.toContain('synthetic-notification-id')
		expect(diagnosticOutput).not.toContain('synthetic-target-id')
		expect(diagnosticOutput).not.toContain('message body')
	})

	it('keeps revocations separate from message upserts and local Delete for Me events', () => {
		const logger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {}, trace: () => {} } as any
		const ev = makeEventBuffer(logger)
		const events: any[] = []
		ev.process(batch => events.push(batch))
		const key = { remoteJid: 'chat@s.whatsapp.net', fromMe: false, id: 'synthetic-target-id' }
		const original: WAMessage = { key, message: { conversation: 'original body' }, messageTimestamp: 1_793_300_000 }
		const localDeleteKey = { remoteJid: 'chat@s.whatsapp.net', fromMe: true, id: 'synthetic-local-delete-id' }
		ev.buffer()
		ev.emit('messages.upsert', { messages: [original], type: 'notify' })
		ev.emit('messages.update', [{
			key,
			revokeTargetKey: key,
			update: { message: null, messageStubType: proto.WebMessageInfo.StubType.REVOKE }
		}])
		ev.emit('messages.delete', { keys: [localDeleteKey] })
		ev.flush()

		expect(events).toHaveLength(1)
		expect(events[0]['messages.upsert'].messages[0].message).toEqual({ conversation: 'original body' })
		expect(events[0]['messages.update'][0].revokeTargetKey).toEqual(key)
		expect(events[0]['messages.delete'].keys).toEqual([localDeleteKey])
	})

	it('does not let a same-key local Delete for Me erase a confirmed revoke update', () => {
		const logger = { debug: () => {}, info: () => {}, warn: () => {}, error: () => {}, trace: () => {} } as any
		const ev = makeEventBuffer(logger)
		const events: any[] = []
		ev.process(batch => events.push(batch))
		const key = { remoteJid: 'chat@g.us', fromMe: false, id: 'synthetic-target-id' }
		ev.buffer()
		ev.emit('messages.update', [{ key, update: { status: 1 } }])
		ev.emit('messages.update', [{
			key,
			revokeTargetKey: key,
			update: { message: null, messageStubType: proto.WebMessageInfo.StubType.REVOKE }
		}])
		ev.emit('messages.delete', { keys: [key] })
		ev.flush()

		expect(events).toHaveLength(1)
		expect(events[0]['messages.update'][0].revokeTargetKey).toEqual(key)
		expect(events[0]['messages.update']).toHaveLength(1)
		expect(events[0]['messages.delete'].keys).toEqual([key])
	})
})
