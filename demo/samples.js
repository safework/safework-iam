var iam = require('./../lib/iam');

var sampleIam = {
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["sm:*"],
            "Resource": [
                "ssrn:ss:sm::200:integration/9999",
                "ssrn:ss:sm::100:assessment/500"
            ]
        },
        {
            "Effect": "Deny",
            "Action": ["sm:SearchResults"],
            "Resource": [
                "ssrn:ss:sm::200:assessment/99"
            ]
        }
    ]
};

var actionCriteria = iam.getActionCriteria('sm:SearchResults', iam.processIamData(sampleIam))

console.log(require('util').inspect(actionCriteria, { depth: null }));
