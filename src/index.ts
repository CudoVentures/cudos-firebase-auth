import * as functions from "firebase-functions";
import corsLib from "cors";
import * as firebaseAdmin from "firebase-admin";
import { coins, decodeSignature, defaultRegistryTypes, encodeSecp256k1Pubkey, fromBase64, Int53, makeAuthInfoBytes, makeSignBytes, makeSignDoc, pubkeyToAddress, Registry, Secp256k1, Secp256k1Signature, sha256, StdSignature, TxBodyEncodeObject } from 'cudosjs'

const COLLECTION = "address-book"!
const firebase = firebaseAdmin.initializeApp();

const cors = corsLib({
    origin: true,
});

export const getNonceToSign = functions.https.onRequest((req, res) =>
    cors(req, res, async () => {
        try {
            if (req.method !== "POST") {
                return res.sendStatus(403);
            }

            if (!req.body.address) {
                return res.sendStatus(400);
            }

            const userDoc = await firebase.firestore().collection(COLLECTION).doc(req.body.address).get();
            if (userDoc.exists) {
                const existingNonce = userDoc.data()?.nonce;
                return res.status(200).json({ nonce: existingNonce });
            }

            const generatedNonce = Math.floor(Math.random() * 1000000).toString();

            const createdUser = await firebase.auth().createUser({
                uid: req.body.address,
            });

            await firebase.firestore().collection(COLLECTION).doc(createdUser.uid).set({
                nonce: generatedNonce,
            });

            return res.status(200).json({ nonce: generatedNonce });
        } catch (err) {
            console.log(err);
            return res.sendStatus(500);
        }
    })
);

export const verifySignedMessage = functions.https.onRequest(
    (req, res) =>
        cors(req, res, async () => {
            try {
                if (req.method !== 'POST') {
                    return res.sendStatus(403);
                }

                if (!req.body.address || !req.body.signature || !req.body.chainId || req.body.sequence === null || req.body.sequence === undefined || !req.body.accountNumber) {
                    return res.sendStatus(400);
                }

                const address = req.body.address as string;
                const sig = req.body.signature as StdSignature;
                const chainId = req.body.chainId as string;
                const sequence = req.body.sequence as number;
                const accountNumber = req.body.accountNumber as number;

                const userDocRef = firebase.firestore().collection(COLLECTION).doc(address);
                const userDoc = await userDocRef.get();
                if (!userDoc.exists) {
                    console.log('user doc does not exist');
                    return res.sendStatus(500);
                }

                const pubKeyRaw = decodeSignature(sig).pubkey;
                const pubkey = {
                    typeUrl: "/cosmos.crypto.secp256k1.PubKey",
                    value: fromBase64(encodeSecp256k1Pubkey(pubKeyRaw).value),
                };

                const amount = coins(0, "acudos")
                const existingNonce = userDoc.data()?.nonce;
                const txBody: TxBodyEncodeObject = {
                    typeUrl: "/cosmos.tx.v1beta1.TxBody",
                    value: {
                        messages: [{
                            typeUrl: "/cosmos.bank.v1beta1.MsgSend",
                            value: { amount },
                        },],
                        memo: `Sign firebase authentication message. Nonce: ${existingNonce}`,
                    },
                };
                const bodyBytes = new Registry(defaultRegistryTypes).encode(txBody);
                const gasLimit = Int53.fromString("0").toNumber();
                const authInfoBytes = makeAuthInfoBytes([{ pubkey, sequence }], amount, gasLimit);
                const signDoc = makeSignDoc(bodyBytes, authInfoBytes, chainId, accountNumber);
                const msgHash = sha256(makeSignBytes(signDoc));

                const valid = await Secp256k1.verifySignature(
                    Secp256k1Signature.fromFixedLength(fromBase64(sig.signature)),
                    msgHash,
                    pubKeyRaw,
                );
                const signer = pubkeyToAddress(encodeSecp256k1Pubkey(pubKeyRaw), "cudos");

                if (!valid || signer !== address) {
                    return res.sendStatus(401);
                }

                await userDocRef.update({
                    nonce: Math.floor(Math.random() * 1000000).toString(),
                });

                const firebaseToken: string = await firebase.auth().createCustomToken(address);

                return res.status(200).json({ token: firebaseToken });
            } catch (err) {
                console.log(err);
                return res.sendStatus(500);
            }
        })
);
