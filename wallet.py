from ellipticCurve import EllipticCurve
from Crypto.Hash import keccak
import random
from ecpy.curves import Point
from txOutput import TxOutput
from smartContract import SmartContract


class Wallet:
    viewAccount = 0
    signAccount = 0

    publicViewKey = 0
    publicSignKey = 0

    privateViewKey = 0
    privateSignKey = 0

    G = EllipticCurve.G
    H = EllipticCurve.H
    cv = EllipticCurve.curve

    k = keccak.new(digest_bits=256)

    def __init__(self, contract, privateViewKey: str, privateSignKey: str, smartContract: SmartContract) -> None:

        self.contract = contract

        self.privateViewKey = int(privateViewKey, 16)
        self.privateSignKey = int(privateSignKey, 16)

        self.publicViewKey = self.G.mul(self.privateViewKey)
        self.publicSignKey = self.G.mul(self.privateSignKey)

        G = EllipticCurve.G
        H = EllipticCurve.H
        cv = EllipticCurve.curve

        self.ownedOutputs = []
        self.smartContract = smartContract

    def createTransaction(self, receiverAmounts: dict):
        # dict of form {(RKV, RKS): amount}

        totalTransactionAmount = 0
        for key in receiverAmounts.keys():
            if (receiverAmounts[key] <= 0):
                receiverAmounts.pop(key)
            else:
                totalTransactionAmount += receiverAmounts[key]

        inputList = []
        sumOfUsedInputs = 0

        # get inputs that will be used in the transaction
        while (sumOfUsedInputs < totalTransactionAmount):
            input = self.ownedOutputs.pop(0)
            sumOfUsedInputs += input["amount"]
            inputList.append(input)

        # add sender as receiver if inputs don't exactly equal totalTransactionAmount
        if (sumOfUsedInputs > totalTransactionAmount):
            keys = (self.getViewKey(), self.getSignKey())
            receiverAmounts[keys] = sumOfUsedInputs - totalTransactionAmount

        # receivers and amounts have been checked and sender added to dict
        t = 0

        outputs = []
        publicOutputs = []

        r = EllipticCurve.randomInt256()  # rG is transaction PubKey

        # create output address and amountCommitments
        sumOutputBF = 0
        for keys in receiverAmounts.keys():

            y = EllipticCurve.randomInt256()

            txAddress = self.createOutputAdress(r=r, t=t, keys=keys)
            amountCommitment = self.createAmountCommitment(
                blindingFactor=y, amount=receiverAmounts[keys])

            outputInfo = {"txAddress": txAddress,
                          "amountCommitment": amountCommitment,
                          "rPubKey": r,
                          "blindingFactor": y,
                          "receiver": keys,
                          "transactionIndex": t}

            publicOutput = {"txAddress": txAddress,
                            "rPubKey": r,
                            "amountCommitment": amountCommitment,
                            "transactionIndex": t
                            }

            outputs.append(outputInfo)
            publicOutputs.append(publicOutput)
            sumOutputBF += y
            t += 1

        # create pseudo commitments
        sumPseudoBF = 0
        commitments = {}
        for input in inputList:
            if input != inputList[-1]:
                ogBF = input["blindingFactor"]
                ogAmount = input["amount"]
                tmp = self.createPseudoCommitment(ogBF=ogBF, ogAmount=ogAmount)
                sumPseudoBF += tmp[1]

            # special case for last value to close loop
            else:
                ogBF = input["blindingFactor"]
                ogAmount = input["amount"]
                tmp = self.createPseudoCommitment(
                    ogBF=ogBF, ogAmount=ogAmount, sumPseudoBF=sumPseudoBF, sumOutputBF=sumOutputBF)

            commitments[frozenset(input)] = {
                "oAC": input["amountCommitment"],
                "nAC": tmp[0],
                "z": tmp[2]
            }

        v = 5  # number of fake ring members / can be set to desired value 

        ringList = []
        mlsags = []
        sendableMLSAGs = []
        for input in inputList:
            p = random.randint(0, v-1)
            i = 0
            ring = []
            fakeMembers = self.getFakeRingMembers(v=v)
            oAC = commitments[frozenset(input)]["oAC"]
            print("# of fake members: " + str(len(fakeMembers)))
            for member in fakeMembers:
                if (i == p):
                    # add original input into ring at random postion p
                    nAC = commitments[frozenset(input)]["nAC"]

                    diff = nAC.sub(oAC).neg()

                    ring.append((input["txAddress"], diff))
                    print("Added original input")

                # add fake members to ring
                nAC = member["amountCommitment"]

                diff = nAC.sub(oAC)

                ring.append((member["txAddress"], diff))
                i += 1

            ringList.append(ring)

            keyImage, k0 = self.createKeyImage(
                inputAdress=input["txAddress"], r=input["r"], t=input["transactionIndex"])

            message = str(self.hash2Hex(str(ringList)))

            r = input["r"]
            t = input["transactionIndex"]

            z = commitments[frozenset(input)]["z"]

            MLSAG = self.createMLSAG(message, ring, p, keyImage, k0, z)

            mlsags.append((MLSAG, keyImage, ring))

            sendableRing = []
            for point in ring:
                tmp = [self.point2Array(point[0]), self.point2Array(point[1])]
                sendableRing.append(tmp)

            for output in publicOutputs:
                output["amountCommitment"] = [
                    output["amountCommitment"].x, output["amountCommitment"].y]
                output["txAddress"] = [
                    output["txAddress"].x, output["txAddress"].y]

            sendableMLSAG = {"c1": MLSAG[0],
                             "keyImage": self.point2Array(keyImage),
                             "rFactors": MLSAG[1:],
                             "inputs": sendableRing
                             }

            sendableMLSAGs.append(sendableMLSAG)
        return (message, mlsags, publicOutputs, sendableMLSAGs)

    def createOutputAdress(self, r: int, t: int, keys: tuple) -> Point:
        # Hash(r * RKV, t) * G + RKS | Monero 4.2.1
        hash = self.hash2Hex(self.point2String(keys[0].mul(r)) + str(t))
        return self.G.mul(hash).add(keys[1])

    def createInitalOutputAdress(self, r: int, t: int) -> Point:
        # used to create new Outputs to this wallet
        # Hash(r * RKV, t) * G + RKS | Monero 4.2.1
        keys = (self.publicViewKey, self.publicSignKey)
        hash = self.hash2Hex(self.point2String((keys[0].mul(r))) + str(t))
        return self.G.mul(hash).add(keys[1])

    def createAmountCommitment(self, blindingFactor: int, amount: int) -> Point:
        # Commitment = y*G + a*H | Monero 5.3
        return self.G.mul(blindingFactor).add(self.H.mul(amount))

    def createPseudoCommitment(self, ogBF: int, ogAmount: int, sumPseudoBF: int = None, sumOutputBF: int = None) -> Point:
        if sumPseudoBF == None and sumOutputBF == None:
            pseudoBF = EllipticCurve.randomInt256()

        else:
            # if last value, find r to create equal difference of sums
            pseudoBF = sumOutputBF - sumPseudoBF

        pseudoCommitment = self.G.mul(pseudoBF).add(self.H.mul(ogAmount))
        z = ogBF - pseudoBF
        return (pseudoCommitment, pseudoBF, z)

    def getFakeRingMembers(self, v: int) -> list:
        allTxoutputs = self.contract.functions.getTXoutputs().call()
        result = []
        for i in range(v):
            output = random.choice(allTxoutputs)
            result.append({
                "rPubKey": output[0],
                "amountCommitment": Point(output[1][0], output[1][1], self.cv),
                "transactionIndex": output[2],
                "txAddress": Point(output[3][0], output[3][1], self.cv)
            })
        return result

    def createKeyImage(self, r: int, t: int, inputAdress: Point):
        # r and t specified by input
        k0 = self.hash2Hex(
            self.point2String(self.publicViewKey.mul(r)) + str(t)
        ) + self.privateSignKey

        inputAdressStr = self.point2String(inputAdress)
        keyImage = self.hash2Point(inputAdressStr).mul(k0)

        return (keyImage, k0)

    def createMLSAG(self, message: str, ring: list, p: int, keyImage: Point, k0: int, z: int) -> list:

        alpha1 = EllipticCurve.randomInt256()
        alpha2 = EllipticCurve.randomInt256()

        r = {}
        for i in range(len(ring)):
            if i != p:
                r[i] = [EllipticCurve.randomInt256(), EllipticCurve.randomInt256()]

        c = {}

        print("Ring length: " + str(len(ring)))
        tmp = (p+1) % len(ring)

        c[tmp] = self.hash2Hex(message
                               + self.point2String(self.G.mul(alpha1))
                               + self.point2String(self.hash2Point(ring[p][0]).mul(alpha1))
                               + self.point2String(self.G.mul(alpha2))
                               )

        for i in range(len(ring)-1):

            j = (i+p+1) % len(ring)
            l = (j+1) % len(ring)

            r1 = r[j][0]
            r2 = r[j][1]

            K1 = ring[j][0]
            K2 = ring[j][1]

            c[l] = self.hash2Hex(message
                                 + self.point2String(self.G.mul(r1).add((K1).mul(c[j])))
                                 + self.point2String((self.hash2Point(K1).mul(r1)).add(keyImage.mul(c[j])))
                                 + self.point2String(self.G.mul(r2).add((K2.mul(c[j]))))
                                 )

        r[p] = ((alpha1 - k0 * c[p]) % (EllipticCurve.L),
                (alpha2 - z * c[p]) % (EllipticCurve.L))  # og

        r1 = r[p][0]
        r2 = r[p][1]

        K1 = self.G.mul(k0)
        K2 = self.H.mul(z)

        signature = [int(c[0])]
        for i in range(len(r)):
            for j in (0, 1):
                signature.append(int(r[i][j]))

        return signature

    def receiveTx(self, tx: TxOutput, blindingFactor: int, amount: int, txAddress: Point):
        print("adress in receive:")
        print(txAddress)
        transactionDetails = {"txAddress": txAddress,
                              "amountCommitment": tx.getAmountCommitment(),
                              "r": tx.getRPubKey(),
                              "blindingFactor": blindingFactor,
                              "amount": amount,
                              "transactionIndex": tx.getTransactionIndex()
                              }
        self.ownedOutputs.append(transactionDetails)

    def point2Array(self, point: Point):
        return [point.x, point.y]

    def point2String(self, point: Point):
        return (str(point.x) + str(point.y))

    def hash(self, message: str) -> str:
        k = keccak.new(digest_bits=256)
        k.update(message.encode('UTF-8'))
        return k.hexdigest()

    def hash2Hex(self, message: str) -> int:
        k = keccak.new(digest_bits=256)
        k.update(message.encode('UTF-8'))
        return int(k.hexdigest(), 16) % EllipticCurve.L

    def hash2Point(self, message: str) -> Point:
        if (type(message) == Point):
            message = self.point2String(message)
        else:
            message = str(message)
        k = keccak.new(digest_bits=256)
        k.update(message.encode('UTF-8'))
        return self.G.mul(int(k.hexdigest(), 16))

    def getViewKey(self) -> Point:
        return self.publicViewKey

    def getSignKey(self) -> Point:
        return self.publicSignKey

    def getViewAccount(self):
        return self.viewAccount

    def getSignAccount(self):
        return self.signAccount
