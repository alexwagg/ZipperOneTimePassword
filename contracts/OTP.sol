pragma solidity ^0.4.18;

// here we are building a simple OTP verification system, that can be integrated into many other systems
// a One Time Password is created as follows:
	// user generates many bytes of randomness (can print it out as a QR-code or something)
	// user creates a relatively complex password
	// user takes keccak256(randomness, passwowrd) as OTPHead
	// user does keccak256( ... rootLength ... keccak256(OTPHead)) as OTPRoot (for some large rootLength)
	// user runs OTPInit_NEW(OTPRoot, rootLength) to initialize the OTP
	// for verification step, user runs keccak256( ... rootLength - 1 ... keccak256(OTPHead))
	// if rootLength - 1 == 0, then user must initialize a NEW OTP.
contract OTP{

	// an OTP structure consists of the currentRoot, and the length of the Root from the head
	// if root == head, then a new OTP must be set up, or the OTP will not verify
	struct OTPConfig {
		bytes32 currentRoot;
		uint256 rootLength;
	}

	event OTPVerificationSuccessful(bool success);

	mapping(address => OTPConfig) userOTPMapping;

	// empty constructor
	function OTP() public {
	}

	///////////////////////////
	// view functions
	///////////////////////////

	function getCurrentRoot(address user) view public returns(bytes32 currentRoot){
		return userOTPMapping[user].currentRoot;
	}

	function getCurrentRootLength(address user) view public returns(uint256 currentRootLength){
		return userOTPMapping[user].rootLength;
	}

	///////////////////////////
	// OTP Functionality
	///////////////////////////

	// initialize an OTP if nothing has been set up yet
	function OTPInit_NEW(bytes32 OTPRoot, uint256 rootLength) public {
		// require user does not have an OTP set up yet
		require(userOTPMapping[msg.sender].currentRoot == 0x0 
			// basic check on the new OTP root length
			&& rootLength > 1 
			// basic check on the OTP Root
			&& OTPRoot != 0x0);

		// if check passes, then send to the initialization function
		OTPInit(OTPRoot, rootLength);
	}

	// verify an OTP, require that one has been set up
	function OTPVerify(bytes32 verifyOTPRoot) public returns(bool success){
		// save in memory for cheap access
		uint256 currentRootLength = userOTPMapping[msg.sender].rootLength;

		// do verification step that keccak256(new root) == currentRoot
		// && verify that the rootLength isn't too short!
		if(keccak256(verifyOTPRoot) == userOTPMapping[msg.sender].currentRoot && currentRootLength > 1){
			// set the OTP to this verified new root, and subtract the length by 1
			OTPInit(verifyOTPRoot, currentRootLength - 1);

			// raise an event and return true
			OTPVerificationSuccessful(true);
			return true;
		}
		// this can be triggered if the OTP verification is incorrect
		// or if the root is too short, in this case the user must call the below function
		OTPVerificationSuccessful(false);
		return false;
	}

	// verify an OTP, and set up another OTP
	function OTPVerify_NEW(bytes verifyOTPRoot, bytes32 newOTPRoot, uint256 newRootLength) public returns(bool success){
		if (keccak256(verifyOTPRoot) == userOTPMapping[msg.sender].currentRoot && newRootLength > 1 && newOTPRoot != 0x0 ){
			// set the OTP to the new OTP as specified by the user
			OTPInit(newOTPRoot, newRootLength);

			// raise an event and return true
			OTPVerificationSuccessful(true);
			return true;
		}
		// this can be triggered if the OTP verification is incorrect
		// or if the basic checks failed on the new OTP config
		OTPVerificationSuccessful(false);
		return false;
	}

	// set up another OTP, internal function, only run if required checks pass
	function OTPInit(bytes32 OTPRoot, uint256 rootLength) internal {
		userOTPMapping[msg.sender].currentRoot = OTPRoot;
		userOTPMapping[msg.sender].rootLength = rootLength;
	}


}