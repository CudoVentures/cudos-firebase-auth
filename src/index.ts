import * as firebaseFunctions from "firebase-functions";
import * as firebaseAdmin from "firebase-admin";
import corsLib from "cors";
import { StdSignature, verifyNonceMsgSigner } from 'cudosjs'

const COLLECTION = "address-book"!
const firebase = firebaseAdmin.initializeApp();

const cors = corsLib({
    origin: true,
});

export const getNonceToSign = firebaseFunctions.https.onRequest((req, res) =>
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

export const verifySignedMessage = firebaseFunctions.https.onRequest((req, res) =>
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

            const existingNonce = userDoc.data()?.nonce;

            if (!await verifyNonceMsgSigner(sig, address, existingNonce, sequence, accountNumber, chainId)) {
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
