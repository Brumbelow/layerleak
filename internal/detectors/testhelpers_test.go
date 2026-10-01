package detectors

// testAWSSecret is a synthetic 40-character AWS-secret-shaped value assembled
// at run time so that no secret-shaped literal sits in the source tree where
// push protection would flag it. Tests splice it into their inputs.
var testAWSSecret = "wJalrXUtnFEMI/K7MDENG" + "/bPxRfiCYDkPqLmNsTu"
