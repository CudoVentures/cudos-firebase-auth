import * as firebaseFunctions from "firebase-functions";
import * as firebaseAdmin from "firebase-admin";
import corsLib from "cors";
import { StdSignature, verifyArbitrarySignature } from 'cudosjs'
import { UserRecord } from "firebase-admin/auth";

const firebase = firebaseAdmin.initializeApp({
    serviceAccountId: process.env.SERVICE_ACCOUNT_EMAIL,
});

const cors = corsLib({
    origin: true,
});

export const getNonceToSignV2 = firebaseFunctions.https.onRequest((req, res) =>
    cors(req, res, async () => {
        try {
            if (req.method !== "POST") {
                return res.sendStatus(403);
            }

            const userAddress = req.body.address
            if (!userAddress || !req.body.collection) {
                return res.sendStatus(400);
            }

            const collection = req.body.collection as string;

            const userDoc = await firebase.firestore().collection(collection).doc(req.body.address).get();
            if (userDoc.exists) {
                const existingNonce = userDoc.data()?.nonce;
                return res.status(200).json({ nonce: existingNonce });
            }

            const generatedNonce = Math.floor(Math.random() * 1000000).toString();

            let user: UserRecord;
            try {
                user = await firebase.auth().getUser(userAddress);
            } catch (error: any) {
                if (error.code === 'auth/user-not-found') {
                    user = await firebase.auth().createUser({
                        uid: userAddress,
                    });
                } else {
                    throw error;
                }
            }
            await firebase.firestore().collection(collection).doc(user.uid).set({
                nonce: generatedNonce,
            });

            return res.status(200).json({ nonce: generatedNonce });
        } catch (err) {
            console.log(err);
            return res.sendStatus(500);
        }
    })
);

export const verifySignedMessageV2 = firebaseFunctions.https.onRequest((req, res) =>
    cors(req, res, async () => {
        try {
            if (req.method !== 'POST') {
                return res.sendStatus(403);
            }

            if (!req.body.address ||
                !req.body.signature ||
                !req.body.collection
            ) {
                return res.sendStatus(400);
            }

            const address = req.body.address as string;
            const sig = req.body.signature as StdSignature;
            const collection = req.body.collection as string;

            const userDocRef = firebase.firestore().collection(collection).doc(address);
            const userDoc = await userDocRef.get();
            if (!userDoc.exists) {
                console.log('user doc does not exist');
                return res.sendStatus(500);
            }

            const existingNonce = userDoc.data()?.nonce;

            if (!verifyArbitrarySignature(sig, address, existingNonce)) {
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
