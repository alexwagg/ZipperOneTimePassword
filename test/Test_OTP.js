const web3 = require('../node_modules/web3/src/index.js');
var OTP_artifact = artifacts.require("./OTP.sol");


contract("Test OTP Verifier", (accounts) => {

	// instance on chain
	var OTP;

	// verification variables
	var randomBytes;
	var password;
	var OTPHead;
	var OTPRoot;

	// chain of OTP's... important
	var OTPChain;

	// deploy a new OTP verification contract before every test
	beforeEach( () => {
		return OTP_artifact.new().then( async (instance) => {
			OTP = instance;

			// init a basic OTP
			randomBytes = "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8";
			password = 'ZipperGlobalPassword';
			
			OTPHead = web3.utils.soliditySha3({type: 'bytes32', value: randomBytes}, {type: 'string', value: password});
			OTPRoot = OTPHead;
			// first element of OTP Chain
			OTPChain = [OTPRoot];

			// calculate the next 10 roots from the head
			for(var i = 0; i < 10; i++){
				// this is the new OTP root
				OTPRoot = web3.utils.soliditySha3({type: 'bytes32', value: OTPRoot});
				// append this root to the chain
				OTPChain.push(OTPRoot.valueOf());
			}

			await OTP.OTPInit_NEW(OTPChain[10], 10, {from: accounts[0]});

			// now OTPChain is of length 11, where there is the head, and then 10 successive roots
			// we init the OTP with the last root, so OTPChain[10] and the length, 10
			// we know that when we have used 10 OTP's, we must re-init a new OTP chain on the next verification
			// step, because the next element will be the head of the chain, and the last OTP (without revealing the secrets!)
		});
	});

	it("Make sure OTP init'ed successfully, and use OTP once, but fail OTP key reuse", async () => {
		
		assert(await OTP.getCurrentRoot(accounts[0]) === OTPChain[10], "OTPRoot did not initialize correctly");
		assert((await OTP.getCurrentRootLength(accounts[0])).toString() === '10', "OTPLength did not initialize correctly");

		var successfulAuth = (await OTP.OTPVerify(OTPChain[9], {from: accounts[0]})).logs[0].args.success;

		assert(successfulAuth === true, "Authorization failed!");

		assert(await OTP.getCurrentRoot(accounts[0]) === OTPChain[9], "OTPRoot did set to previous root");
		assert((await OTP.getCurrentRootLength(accounts[0])).toString() === '9', "OTPLength did not decrement");

		// try to use the same hash again should fail -- ONE time password
		successfulAuth = (await OTP.OTPVerify(OTPChain[9], {from: accounts[0]})).logs[0].args.success;

		assert(successfulAuth === false, "Authorization successful, but can only use password once!");

		assert(await OTP.getCurrentRoot(accounts[0]) === OTPChain[9], "OTPRoot should be same");
		assert((await OTP.getCurrentRootLength(accounts[0])).toString() === '9', "OTPLength should be same");
	});

	it("should successfully use OTP 9 times, and then fail the 10th time", async () => {

		var successfulAuth;

		for (var i = 9; i > 0; i--){
			successfulAuth = (await OTP.OTPVerify(OTPChain[i], {from: accounts[0]})).logs[0].args.success;

			assert(successfulAuth === true, "OTP not a success on the " + i.toString() + "th round");
			assert(await OTP.getCurrentRoot(accounts[0]) === OTPChain[i], "OTPRoot did set on the " + i.toString() + "th round");
			assert((await OTP.getCurrentRootLength(accounts[0])).toString() === i.toString(), "OTPLength did not set on the " + i.toString() + "th round");
		}

		// now, we are using the OTPHead to verify the last OTP, this must fail because the OTP chain must be reset here
		successfulAuth = (await OTP.OTPVerify(OTPChain[0], {from: accounts[0]})).logs[0].args.success;

		assert(successfulAuth === false, "Authorization successful, but should not be! OTP has expired!");

		assert(await OTP.getCurrentRoot(accounts[0]) === OTPChain[1], "OTPRoot should be same");
		assert((await OTP.getCurrentRootLength(accounts[0])).toString() === '1', "OTPLength should be same");
	});

	it("should successfully use OTP 9 times, then verify + reset OTP for the 10th time, then use again 9 times", async () => {
		// first 9 times
		var successfulAuth;

		for (var i = 9; i > 0; i--){
			successfulAuth = (await OTP.OTPVerify(OTPChain[i], {from: accounts[0]})).logs[0].args.success;

			assert(successfulAuth === true, "OTP not a success on the " + i.toString() + "th round");
			assert(await OTP.getCurrentRoot(accounts[0]) === OTPChain[i], "OTPRoot did set on the " + i.toString() + "th round");
			assert((await OTP.getCurrentRootLength(accounts[0])).toString() === i.toString(), "OTPLength did not set on the " + i.toString() + "th round");
		}

		// 10th time, lets reset with the same randomness but a new password...
		var lastValidOTP = OTPChain[0];

		password = 'ZipperGlobalPasswordNumber2';
		OTPHead = web3.utils.soliditySha3({type: 'bytes32', value: randomBytes}, {type: 'string', value: password});
		OTPRoot = OTPHead;
		// first element of OTP Chain
		OTPChain = [OTPRoot];

		// calculate the next 10 roots from the head
		for(i = 0; i < 10; i++){
			// this is the new OTP root
			OTPRoot = web3.utils.soliditySha3({type: 'bytes32', value: OTPRoot});
			// append this root to the chain
			OTPChain.push(OTPRoot.valueOf());
		}

		// now use the function OTPVerify_NEW() to submit this new OTPRoot & length
		successfulAuth = (await OTP.OTPVerify_NEW(lastValidOTP, OTPChain[10], 10, {from: accounts[0]})).logs[0].args.success;
		
		assert(successfulAuth === true, "Authorization failed!");
		assert(await OTP.getCurrentRoot(accounts[0]) === OTPChain[10], "OTPRoot did not initialize correctly");
		assert((await OTP.getCurrentRootLength(accounts[0])).toString() === '10', "OTPLength did not initialize correctly");

		// do another round of OTP verification
		for (i = 9; i > 0; i--){
			successfulAuth = (await OTP.OTPVerify(OTPChain[i], {from: accounts[0]})).logs[0].args.success;

			assert(successfulAuth === true, "OTP not a success on the " + i.toString() + "th round");
			assert(await OTP.getCurrentRoot(accounts[0]) === OTPChain[i], "OTPRoot did set on the " + i.toString() + "th round");
			assert((await OTP.getCurrentRootLength(accounts[0])).toString() === i.toString(), "OTPLength did not set on the " + i.toString() + "th round");
		}
	});

	it("shouldn't allow a user to overwrite the OTP if he already has one established", async () => {
		try{
			// try and init the OTP chain with some random hash and number
			await OTP.OTPInit_NEW(web3.utils.sha3('random hash'), 7, {from: accounts[0]});
			assert(false, "user was allowed to overwrite OTP!");
		}
		catch(error){
			assert(error.message == 'VM Exception while processing transaction: revert', "incorrect error type...");
		}
	});
})