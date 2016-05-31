var iam = require('./../lib/iam');

var iamFileData  = {
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["CanRead"],
      "Resource": [
        "ssrn:ss:iam:::account/100/assestmentgroup/*/customquestions"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["CanUpdate","CanDelete","CanCreate"],
      "Resource": "ssrn:ss:iam:::account/100/assestmentgroup/1/customquestions"
    },
    {
      "Effect": "Deny",
      "Action": ["CanUpdate"],
      "Resource": [
        "ssrn:ss:iam:::account/100/assestmentgroup/2/customquestions"
      ]
    }
  ]
};

var testData = {
  "Test": [
    {"Resource" : "ssrn:ss:iam:::account/100/assestmentgroup/2/customquestions", "Action": "CanUpdate", "Result": "false"},
    {"Resource" : "ssrn:ss:iam:::account/100/assestmentgroup/2/customquestions", "Action": "CanRead", "Result": "true"}
  ]
}

var processedIamFileData = iam.processIamData( iamFileData );

for ( var i = 0; i < testData.Test.length; i++ ){
    var test = testData.Test[i];
    var iamResult = iam.authorize( test.Resource, test.Action, processedIamFileData );
    console.log( "index: "+ i + " " +iamResult  + " " +  test.Result);
}
