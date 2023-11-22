import { randomBytes } from '@noble/hashes/utils';
import { CashuMint } from './CashuMint.js';
import * as dhke from './DHKE.js';
import { BlindedMessage } from './model/BlindedMessage.js';
import {
	AmountPreference,
	BlindedMessageData,
	BlindedTransaction, MeltResponse,
	MintKeys,
	PayLnInvoiceResponse,
	PaymentPayload,
	Proof,
	ReceiveResponse,
	ReceiveTokenEntryResponse,
	SendResponse,
	SerializedBlindedMessage,
	SerializedBlindedSignature,
	SplitPayload,
	TokenEntry
} from './model/types/index.js';
import {
	bytesToNumber,
	cleanToken,
	deriveKeysetId,
	getDecodedToken,
	getDefaultAmountPreference, joinUrls,
	splitAmount
} from './utils.js';
import * as bip39 from "bip39";
import BIP32Factory from 'bip32';
import * as ecc from 'tiny-secp256k1';
import { secp256k1 } from '@noble/curves/secp256k1';
import { BIP32Interface } from 'bip32';
import crypto from "crypto";
import request from "./request";
const bip32 = BIP32Factory(ecc);

/**
 * Class that represents a Cashu wallet.
 * This class should act as the entry point for this library
 */
class CashuWallet {
	private _keys: MintKeys;
	private _keysetId = '';
	mint: CashuMint;
	private seed: Buffer | undefined;
	private mnemonic: string | undefined;
	private privateKey: BIP32Interface | undefined;
	private node: BIP32Interface | undefined;
	private proofs: any[] = [];

	/**
	 * @param keys public keys from the mint
	 * @param mnemonic mnemonic to derive the private key from
	 * @param mint Cashu mint instance is used to make api calls
	 */
	constructor(mint: CashuMint, mnemonic: string, keys?: MintKeys) {
		this._keys = keys || {};
		this.mint = mint;
		this.seed = bip39.mnemonicToSeedSync(mnemonic);
		this.mnemonic = mnemonic;
		this.node = bip32.fromSeed(this.seed);
		this.privateKey = this.node.derivePath("m/129372'/0'/0'/0'");
		if (keys) {
			this._keysetId = deriveKeysetId(this._keys);
		}
	}

	get keys(): MintKeys {
		return this._keys;
	}
	set keys(keys: MintKeys) {
		this._keys = keys;
		this._keysetId = deriveKeysetId(this._keys);
	}
	get keysetId(): string {
		return this._keysetId;
	}
	/**
	 * returns proofs that are already spent (use for keeping wallet state clean)
	 * @param proofs (only the 'secret' field is required)
	 * @returns
	 */
	async checkProofsSpent<T extends { secret: string }>(proofs: Array<T>): Promise<Array<T>> {
		const payload = {
			//send only the secret
			proofs: proofs.map((p) => ({ secret: p.secret }))
		};
		const { spendable } = await this.mint.check(payload);
		return proofs.filter((_, i) => !spendable[i]);
	}
	/**
	 * Starts a minting process by requesting an invoice from the mint
	 * @param amount Amount requesting for mint.
	 * @returns the mint will create and return a Lightning invoice for the specified amount
	 */
	requestMint(amount: number) {
		return this.mint.requestMint(amount);
	}

	/**
	 * Executes a payment of an invoice on the Lightning network.
	 * The combined amount of Proofs has to match the payment amount including fees.
	 * @param invoice
	 * @param proofsToSend the exact amount to send including fees
	 * @param feeReserve? optionally set LN routing fee reserve. If not set, fee reserve will get fetched at mint
	 */
	async payLnInvoice(
		invoice: string,
		proofsToSend: Array<Proof>,
		feeReserve?: number
	): Promise<PayLnInvoiceResponse> {
		const paymentPayload = this.createPaymentPayload(invoice, proofsToSend);
		if (!feeReserve) {
			feeReserve = await this.getFee(invoice);
		}
		const { blindedMessages, secrets, rs } = this.createBlankOutputs(feeReserve);
		const payData = await this.mint.melt({
			...paymentPayload,
			outputs: blindedMessages
		});
		return {
			isPaid: payData.paid ?? false,
			preimage: payData.preimage,
			change: payData?.change
				? dhke.constructProofs(payData.change, rs, secrets, await this.getKeys(payData.change))
				: [],
			newKeys: await this.changedKeys(payData?.change)
		};
	}
	/**
	 * Estimate fees for a given LN invoice
	 * @param invoice LN invoice that needs to get a fee estimate
	 * @returns estimated Fee
	 */
	async getFee(invoice: string): Promise<number> {
		const { fee } = await this.mint.checkFees({ pr: invoice });
		return fee;
	}

	createPaymentPayload(invoice: string, proofs: Array<Proof>): PaymentPayload {
		return {
			pr: invoice,
			proofs: proofs
		};
	}
	/**
	 * Use a cashu token to pay an ln invoice
	 * @param invoice Lightning invoice
	 * @param token cashu token
	 */
	payLnInvoiceWithToken(invoice: string, token: string): Promise<PayLnInvoiceResponse> {
		const decodedToken = getDecodedToken(token);
		const proofs = decodedToken.token
			.filter((x) => x.mint === this.mint.mintUrl)
			.flatMap((t) => t.proofs);
		return this.payLnInvoice(invoice, proofs);
	}
	/**
	 * Receive an encoded Cashu token
	 * @param encodedToken Cashu token
	 * @param preference optional preference for splitting proofs into specific amounts
	 * @returns New token with newly created proofs, token entries that had errors, and newKeys if they have changed
	 */
	async receive(encodedToken: string, preference?: Array<AmountPreference>): Promise<ReceiveResponse> {
		const { token } = cleanToken(getDecodedToken(encodedToken));
		const tokenEntries: Array<TokenEntry> = [];
		const tokenEntriesWithError: Array<TokenEntry> = [];
		let newKeys: MintKeys | undefined;
		for (const tokenEntry of token) {
			if (!tokenEntry?.proofs?.length) {
				continue;
			}
			try {
				const {
					proofsWithError,
					proofs,
					newKeys: newKeysFromReceive
				} = await this.receiveTokenEntry(tokenEntry, preference);
				if (proofsWithError?.length) {
					tokenEntriesWithError.push(tokenEntry);
					continue;
				}
				tokenEntries.push({ mint: tokenEntry.mint, proofs: [...proofs] });
				if (!newKeys) {
					newKeys = newKeysFromReceive;
				}
			} catch (error) {
				console.error(error);
				tokenEntriesWithError.push(tokenEntry);
			}
		}
		return {
			token: { token: tokenEntries },
			tokensWithErrors: tokenEntriesWithError.length ? { token: tokenEntriesWithError } : undefined,
			newKeys
		};
	}

	/**
	 * Receive a single cashu token entry
	 * @param tokenEntry a single entry of a cashu token
	 * @param preference optional preference for splitting proofs into specific amounts.
	 * @returns New token entry with newly created proofs, proofs that had errors, and newKeys if they have changed
	 */
	async receiveTokenEntry(tokenEntry: TokenEntry, preference?: Array<AmountPreference>): Promise<ReceiveTokenEntryResponse> {
		const proofsWithError: Array<Proof> = [];
		const proofs: Array<Proof> = [];
		let newKeys: MintKeys | undefined;
		try {
			const amount = tokenEntry.proofs.reduce((total, curr) => total + curr.amount, 0);
			if (!preference) {
				preference = getDefaultAmountPreference(amount)
			}
			const { payload, blindedMessages } = this.createSplitPayload(
				amount,
				tokenEntry.proofs,
				preference
			);
			const { promises, error } = await CashuMint.split(tokenEntry.mint, payload);
			const newProofs = dhke.constructProofs(
				promises,
				blindedMessages.rs,
				blindedMessages.secrets,
				await this.getKeys(promises, tokenEntry.mint)
			);
			proofs.push(...newProofs);
			newKeys =
				tokenEntry.mint === this.mint.mintUrl
					? await this.changedKeys([...(promises || [])])
					: undefined;
		} catch (error) {
			console.error(error);
			proofsWithError.push(...tokenEntry.proofs);
		}
		return {
			proofs,
			proofsWithError: proofsWithError.length ? proofsWithError : undefined,
			newKeys
		};
	}

	/**
	 * Splits and creates sendable tokens
	 * if no amount is specified, the amount is implied by the cumulative amount of all proofs
	 * if both amount and preference are set, but the preference cannot fulfill the amount, then we use the default split
	 * @param amount amount to send while performing the optimal split (least proofs possible). can be set to undefined if preference is set
	 * @param proofs proofs matching that amount
	 * @param preference optional preference for splitting proofs into specific amounts. overrides amount param
	 * @returns promise of the change- and send-proofs
	 */
	async send(
		amount: number,
		proofs: Array<Proof>,
		preference?: Array<AmountPreference>
	): Promise<SendResponse> {
		if (preference) {
			amount = preference?.reduce((acc, curr) => acc + curr.amount * curr.count, 0);
		}

		let amountAvailable = 0;
		const proofsToSend: Array<Proof> = [];
		const proofsToKeep: Array<Proof> = [];
		proofs.forEach((proof) => {
			if (amountAvailable >= amount) {
				proofsToKeep.push(proof);
				return
			}
			amountAvailable = amountAvailable + proof.amount;
			proofsToSend.push(proof);
		});

		if (amount > amountAvailable) {
			throw new Error('Not enough funds available');
		}
		if (amount < amountAvailable || preference) {
			const { amountKeep, amountSend } = this.splitReceive(amount, amountAvailable);
			const { payload, blindedMessages } = this.createSplitPayload(amountSend, proofsToSend, preference);
			const { promises } = await this.mint.split(payload);
			const proofs = dhke.constructProofs(
				promises,
				blindedMessages.rs,
				blindedMessages.secrets,
				await this.getKeys(promises)
			);
			// sum up proofs until amount2 is reached
			const splitProofsToKeep: Array<Proof> = [];
			const splitProofsToSend: Array<Proof> = [];
			let amountKeepCounter = 0;
			proofs.forEach((proof) => {
				if (amountKeepCounter < amountKeep) {
					amountKeepCounter += proof.amount;
					splitProofsToKeep.push(proof);
					return;

				}
				splitProofsToSend.push(proof);
			});
			return {
				returnChange: [...splitProofsToKeep, ...proofsToKeep],
				send: splitProofsToSend,
				newKeys: await this.changedKeys([...(promises || [])])
			};
		}
		return { returnChange: proofsToKeep, send: proofsToSend };
	}

	/**
	 * Request tokens from the mint
	 * @param amount amount to request
	 * @param hash hash to use to identify the request
	 * @returns proofs and newKeys if they have changed
	 */
	async requestTokens(
		amount: number,
		hash: string,
		AmountPreference?: Array<AmountPreference>
	): Promise<{ proofs: Array<Proof>; newKeys?: MintKeys }> {
		const { blindedMessages, secrets, rs } = this.createRandomBlindedMessages(
			amount,
			AmountPreference
		);
		const payloads = { outputs: blindedMessages };
		const { promises } = await this.mint.mint(payloads, hash);
		return {
			proofs: dhke.constructProofs(promises, rs, secrets, await this.getKeys(promises)),
			newKeys: await this.changedKeys(promises)
		};
	}

	/**
	 * Initialize the wallet with the mints public keys
	 */
	private async initKeys() {
		if (!this.keysetId || !Object.keys(this.keys).length) {
			this.keys = await this.mint.getKeys();
			this._keysetId = deriveKeysetId(this.keys);
		}
	}

	/**
	 * Check if the keysetId has changed and return the new keys
	 * @param promises array of promises to check
	 * @returns new keys if they have changed
	 */
	private async changedKeys(
		promises: Array<SerializedBlindedSignature | Proof> = []
	): Promise<MintKeys | undefined> {
		await this.initKeys();
		if (!promises?.length) {
			return undefined;
		}
		if (!promises.some((x) => x.id !== this.keysetId)) {
			return undefined;
		}
		const maybeNewKeys = await this.mint.getKeys();
		const keysetId = deriveKeysetId(maybeNewKeys);
		return keysetId === this.keysetId ? undefined : maybeNewKeys;
	}

	/**
	 * Get the mint's public keys for a given set of proofs
	 * @param arr array of proofs
	 * @param mint optional mint url
	 * @returns keys
	 */
	private async getKeys(arr: Array<SerializedBlindedSignature>, mint?: string): Promise<MintKeys> {
		await this.initKeys();
		if (!arr?.length || !arr[0]?.id) {
			return this.keys;
		}
		const keysetId = arr[0].id;
		if (this.keysetId === keysetId) {
			return this.keys;
		}

		const keys =
			!mint || mint === this.mint.mintUrl
				? await this.mint.getKeys(arr[0].id)
				: await CashuMint.getKeys(mint, arr[0].id);
		return keys;
	}

	/**
	 * Creates a split payload
	 * @param amount1 amount to keep
	 * @param amount2 amount to send
	 * @param proofsToSend proofs to split
	 * @returns
	 */
	private createSplitPayload(
		amount: number,
		proofsToSend: Array<Proof>,
		preference?: Array<AmountPreference>
	): {
		payload: SplitPayload;
		blindedMessages: BlindedTransaction;
	} {
		const totalAmount = proofsToSend.reduce((total, curr) => total + curr.amount, 0);
		const keepBlindedMessages = this.createRandomBlindedMessages(totalAmount - amount);
		const sendBlindedMessages = this.createRandomBlindedMessages(amount, preference);

		// join keepBlindedMessages and sendBlindedMessages
		const blindedMessages: BlindedTransaction = {
			blindedMessages: [
				...keepBlindedMessages.blindedMessages,
				...sendBlindedMessages.blindedMessages
			],
			secrets: [...keepBlindedMessages.secrets, ...sendBlindedMessages.secrets],
			rs: [...keepBlindedMessages.rs, ...sendBlindedMessages.rs],
			amounts: [...keepBlindedMessages.amounts, ...sendBlindedMessages.amounts]
		};

		const payload = {
			proofs: proofsToSend,
			outputs: [...blindedMessages.blindedMessages]
		};
		return { payload, blindedMessages };
	}
	private splitReceive(
		amount: number,
		amountAvailable: number
	): { amountKeep: number; amountSend: number } {
		const amountKeep: number = amountAvailable - amount;
		const amountSend: number = amount;
		return { amountKeep, amountSend };
	}

	/**
	 * Creates blinded messages for a given amount
	 * @param amount amount to create blinded messages for
	 * @returns blinded messages, secrets, rs, and amounts
	 */
	private createRandomBlindedMessages(
		amount: number,
		amountPreference?: Array<AmountPreference>
	): BlindedMessageData & { amounts: Array<number> } {
		const blindedMessages: Array<SerializedBlindedMessage> = [];
		const secrets: Array<Uint8Array> = [];
		const rs: Array<bigint> = [];
		const amounts = splitAmount(amount, amountPreference);
		for (let i = 0; i < amounts.length; i++) {
			const secret = randomBytes(32);
			secrets.push(secret);
			const { B_, r } = dhke.blindMessage(secret);
			rs.push(r);
			const blindedMessage = new BlindedMessage(amounts[i], B_);
			blindedMessages.push(blindedMessage.getSerializedBlindedMessage());
		}
		return { blindedMessages, secrets, rs, amounts };
	}

	/**
	 * Creates NUT-08 blank outputs (fee returns) for a given fee reserve
	 * See: https://github.com/cashubtc/nuts/blob/main/08.md
	 * @param feeReserve amount to cover with blank outputs
	 * @returns blinded messages, secrets, and rs
	 */
	private createBlankOutputs(feeReserve: number): BlindedMessageData {
		const blindedMessages: Array<SerializedBlindedMessage> = [];
		const secrets: Array<Uint8Array> = [];
		const rs: Array<bigint> = [];
		const count = Math.ceil(Math.log2(feeReserve)) || 1;
		for (let i = 0; i < count; i++) {
			const secret = randomBytes(32);
			secrets.push(secret);
			const { B_, r } = dhke.blindMessage(secret);
			rs.push(r);
			const blindedMessage = new BlindedMessage(0, B_);
			blindedMessages.push(blindedMessage.getSerializedBlindedMessage());
		}

		return { blindedMessages, secrets, rs };
	}
	private async  restorePromises(outputs: any[], secrets: string[], rs: Uint8Array[], derivationPaths: string[]) {
		// Call the super().restore_promises method and await the result
		const [restoredOutputs, restoredPromises] = await this.requestRestorePromises(outputs);
		// console.log('restoredOutputs', restoredOutputs)
		// console.log('restoredPromises', restoredPromises)
		// Find matching indices between restoredOutputs and outputs
		const matchingIndices = outputs.reduce((indices, output, idx) => {
			if (restoredOutputs.some((restoredOutput: any) => restoredOutput.B_ === output.B_)) {
				indices.push(idx);
			}
			return indices;
		}, []);

		// Filter secrets and rs based on matching indices
		const filteredSecrets: Uint8Array[] = matchingIndices.map((idx: any) => {
			const enc = new TextEncoder();
			const secretUInt8 = enc.encode(secrets[idx]);
			return secretUInt8;
		});
		const filteredRs: bigint[] = matchingIndices.map((idx: any) => bytesToNumber(rs[idx]));
		// console.log('restoredPromises',restoredPromises)
		// Call the _construct_proofs method with the restored promises, filtered secrets, rs, and derivation paths
		const proofs = dhke.constructProofs(restoredPromises, filteredRs, filteredSecrets, this._keys!);

		console.log(`Restored ${restoredPromises.length} promises`);

		// Call the _store_proofs method with the generated proofs
		// await this._store_proofs(proofs);

		// Append the proofs to the proofs in memory
		proofs.forEach(proof => {
			if (!this.proofs.some(existingProof => existingProof.secret === proof.secret)) {
				this.proofs.push(proof);
			}
		});

		return proofs;
	}
	private async generateDeterministicSecret(counter: number): Promise<[Uint8Array, Uint8Array, string]> {
		if (!this.node) {
			throw new Error("node not initialized");
		}
		if (!this.mnemonic) {
			throw new Error("cashWallet not initialized");
		}
		const keysetIdBytes = Buffer.from(this._keysetId, 'base64');
		const keysetIdBigInt = BigInt('0x' + keysetIdBytes.toString('hex'));
		const maxChildKeys = BigInt(2 ** 31 - 1);
		const keyestId = Number(keysetIdBigInt % maxChildKeys);

		const tokenDerivationPath = `m/129372'/0'/${keyestId}'/${counter}'`;
		const secretDerivationPath = `${tokenDerivationPath}/0`;

		// console.log(`secret derivation path: ${secretDerivationPath}`);
		const { privateKey: secret }= this.node.derivePath(secretDerivationPath);
		const rDerivationPath = `${tokenDerivationPath}/1`;
		const { privateKey: r }= this.node.derivePath(rDerivationPath);

		return [
			new Uint8Array(secret!),
			new Uint8Array(r!),
			tokenDerivationPath
		]
	}
	private async generateSecretsFromTo(fromCounter: number, toCounter: number): Promise<[string[], Uint8Array[], string[]]> {
		if (fromCounter > toCounter) {
			throw new Error("fromCounter must be smaller than toCounter");
		}

		const secretCounters = [];
		for (let c = fromCounter; c <= toCounter; c++) {
			secretCounters.push(c);
		}

		const secretsRsDerivationPaths = [];
		for (const secretCounter of secretCounters) {
			const secretRsDerivationPath = await this.generateDeterministicSecret(secretCounter);
			secretsRsDerivationPaths.push(secretRsDerivationPath);
		}

		const secrets = secretsRsDerivationPaths.map((s) => {
			const secretHash = crypto.createHash('sha256');
			secretHash.update(s[0]);
			return secretHash.digest('hex');
		})
		// console.log('secrets', secrets)
		//     .map(s => {
		//     const encoder = new TextEncoder();
		//     const uint8Array = encoder.encode(s);
		//     return uint8Array;
		// });
		const rs: Uint8Array[] = secretsRsDerivationPaths.map((s) => {
			return s[1]
		});

		const derivationPaths = secretsRsDerivationPaths.map((s) => s[2]);

		return [secrets, rs, derivationPaths];
	}
	private async restorePromisesFromTo(fromCounter: number, toCounter: number) {
		const [secrets, rs, derivationPaths] = await this.generateSecretsFromTo(fromCounter, toCounter);
		// console.log('secrets', secrets)
		// console.log('rs', rs)
		// console.log('derivationPaths', derivationPaths)
		// Create a dummy amounts array with the same length as secrets
		const amountsDummy = Array(secrets.length).fill(1);
		// console.log('amountsDummy', amountsDummy)
		const [regeneratedOutputs, _] = this.constructOutputs(amountsDummy, secrets, rs);
		// console.log('regeneratedOutputs', regeneratedOutputs)
		// // Ask the mint to reissue the promises
		const proofs = await this.restorePromises(
			regeneratedOutputs,
			secrets,
			rs,
			derivationPaths,
		);
		// console.log('proofs', proofs)

		return proofs;
	}
	private async requestRestorePromises(outputs: any[]) {
		try {
			// Create the payload
			const payload = {
				outputs: outputs
			};

			// Make the POST request to the API
			const response = await request<any>({
				endpoint: joinUrls(this.mint.mintUrl, '/restore'),
				method: 'POST',
				requestBody: payload
			})


			// Check for errors in the response (handle this according to your needs)
			if (response.code !== 200) {
				throw new Error(`Failed to restore promises. Status code: ${response.code}`);
			}

			// Parse the response JSON
			const responseObj = response;
			// console.log('responseObj', responseObj)
			// Assuming you have appropriate data structures to parse the response
			const returnObj = {
				outputs: responseObj.outputs,
				promises: responseObj.promises
			};

			return [returnObj.outputs, returnObj.promises];
		} catch (error) {
			// Handle any errors (e.g., network errors, API errors)
			throw new Error(`Error restoring promises: ${error}`);
		}
	}
	private constructOutputs(amounts: number[], secrets: string[], rs: Uint8Array[] = []) {
		// Check if the lengths of amounts and secrets are equal
		if (amounts.length !== secrets.length) {
			throw new Error(`Length of amounts (${amounts.length}) is not equal to length of secrets (${secrets.length})`);
		}

		const outputs = [];
		const rsReturn = [];

		// If rs is not provided, initialize it with null values
		const rs_ = rs.length === 0 ? new Array(amounts.length).fill(null) : rs;

		for (let i = 0; i < secrets.length; i++) {
			const secret = secrets[i];
			const amount = amounts[i];
			let r = rs_[i];

			// Call the b_dhke.step1_alice function here and assign B_ and r values
			// You'll need to replace this with your actual implementation
			const { B_, r: newR } = this.step1Alice(secret, r);

			rsReturn.push(newR);

			// Create a BlindedMessage object with the required properties
			const output = {
				amount: amount,
				B_: B_.toHex() // Make sure to serialize B_ correctly
			};

			outputs.push(output);

			// console.log(`Constructing output: ${JSON.stringify(output)}, r: ${newR}`);
		}

		return [outputs, rsReturn];
	}
	private step1Alice(secret: string, r: Uint8Array) {
		const enc = new TextEncoder();
		const secretUInt8 = enc.encode(secret);

		const Y = dhke.hashToCurve(secretUInt8);
		if (!r) {
			r = secp256k1.utils.randomPrivateKey();
		}
		// const rG = secp256k1.ProjectivePoint.BASE.multiply(r);


		const B_ = Y.add(secp256k1.ProjectivePoint.fromPrivateKey(r));
		return { B_, r };

	}
	private async invalidate(proofs: any[], checkSpendable = true) {
		const invalidatedProofs: any[] = [];

		if (checkSpendable) {

			const proofStates = await this.mint!.check({proofs});

			for (let i = 0; i < proofStates.spendable.length; i++) {
				if (!proofStates.spendable[i]) {
					invalidatedProofs.push(proofs[i]);
				}
			}
		} else {
			invalidatedProofs.push(...proofs);
		}

		if (invalidatedProofs.length > 0) {
			console.log(`Invalidating ${invalidatedProofs.length} proofs worth ${this.sumProofs(invalidatedProofs)} sat.`);
		}

		// Assuming you have a database connection and an invalidateProof function
		// const conn = await this.db.connect();
		// for (const p of invalidatedProofs) {
		//     await invalidateProof(p, this.db, conn);
		// }

		const invalidateSecrets = invalidatedProofs.map(p => p.secret);
		this.proofs = this.proofs.filter(p => !invalidateSecrets.includes(p.secret));

		// Filter out invalidated proofs from the original proofs list
		const remainingProofs = proofs.filter(p => !invalidatedProofs.includes(p));

		return remainingProofs;
	}
	sumProofs(proofs: any[]) {
		return proofs.reduce((sum, p) => sum + p.amount, 0);
	}
	static generateMnemonic(): string {
		return bip39.generateMnemonic();
	}
	async restore() {
		console.log("Restoring tokens...");
		let stopCounter = 0;
		const to = 2;
		const batch = 25;
		let spendableProofs = [];
		const counterBefore = 0

		let i = counterBefore;
		let nLastRestoredProofs = 0;

		while (stopCounter < to) {
			console.log(`Restoring token ${i} to ${i + batch - 1}...`);
			const restoredProofs = await this.restorePromisesFromTo(i, i + batch - 1);
			// console.log('restoredProofs length', restoredProofs.length)
			if (restoredProofs.length === 0) {
				stopCounter++;
			}

			spendableProofs = await this.invalidate(restoredProofs);
			// console.log('spendableProofs', spendableProofs)
			if (spendableProofs.length) {
				nLastRestoredProofs = spendableProofs.length;
				console.log(`Restored ${this.sumProofs(restoredProofs)} sat`);
			}

			i += batch;
		}
		//
		// Restore the secret counter to its previous value for the last round
		const revertCounterBy = batch * to + nLastRestoredProofs;
		console.log(`Reverting secret counter by ${revertCounterBy}`);

		if (nLastRestoredProofs === 0) {
			console.log("No tokens restored.");
			return;
		}
		return {
			spendableProofs,
		}

	}

}

export { CashuWallet };
