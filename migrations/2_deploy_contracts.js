var OTP = artifacts.require('./OTP.sol');

module.exports = function(deployer, network, accounts){
	if (network == 'development'){
		deployer.deploy(OTP);
	}