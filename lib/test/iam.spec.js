var expect = require('chai').expect,
    iam = require('./../iam');

describe('#processIamData', function(){
    it('Processes each Resource into a Regular Expression', function(){

        var sampleIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["CanRead"],
                    "Resource": [
                        "organisation:partition:iam:::account/100/service/*/sub-service"
                    ]
                }
            ]
        };

        var processedIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["CanRead"],
                    "ActionRegex": ["^CanRead$"],
                    "Resource": [
                        "organisation:partition:iam:::account/100/service/*/sub-service"
                    ],
                    "ResourceRegex": [
                        "^organisation:partition:iam:::account/100/service/([0-9A-Za-z_]+/?)*/sub-service$"
                    ]
                }
            ]
        };

        expect(iam.processIamData(sampleIam)).to.deep.equal(processedIam);
    });

    it('While Processing each Resource and Action into a Regular Expression Remove all Hidden Characters', function(){

        var sampleIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["*:*"],
                    "Resource": [
                        "organisation:partition:service::​*:*"          //this one has hidden character
                    ]
                }
            ]
        };

        var processedIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["*:*"],
                    "ActionRegex": ["^([0-9A-Za-z]+)*:([0-9A-Za-z]+)*$"],
                    "Resource": [
                        "organisation:partition:service::​*:*"
                    ],
                    "ResourceRegex": [
                        "^organisation:partition:service::([0-9A-Za-z_]+/?)*:([0-9A-Za-z_]+/?)*$"
                    ]
                }
            ]
        };

        expect(iam.processIamData(sampleIam)).to.deep.equal(processedIam);
    });


});

describe('During IAM rule processing', function(){
    it('Processes each Resource into a Regular Expression', function(){

        var sampleIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["CanRead"],
                    "Resource": [
                        "organisation:partition:iam:::account/100/service/*/sub-service"
                    ]
                }
            ]
        };

        var processedIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["CanRead"],
                    "ActionRegex": ["^CanRead$"],
                    "Resource": [
                        "organisation:partition:iam:::account/100/service/*/sub-service"
                    ],
                    "ResourceRegex": [
                        "^organisation:partition:iam:::account/100/service/([0-9A-Za-z_]+/?)*/sub-service$"
                    ]
                }
            ]
        };

        expect(iam.processIamData(sampleIam)).to.deep.equal(processedIam);
    });

    it('should successfully process without an array for actions.', function(){

        var sampleIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "CanRead",
                    "Resource": [
                        "organisation:partition:iam:::account/100/service/*/sub-service"
                    ]
                }
            ]
        };

        var processedIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "CanRead",
                    "ActionRegex": ["^CanRead$"],
                    "Resource": [
                        "organisation:partition:iam:::account/100/service/*/sub-service"
                    ],
                    "ResourceRegex": [
                        "^organisation:partition:iam:::account/100/service/([0-9A-Za-z_]+/?)*/sub-service$"
                    ]
                }
            ]
        };

        expect(iam.processIamData(sampleIam)).to.deep.equal(processedIam);
    });

    it('should successfully process without an array for resource.', function(){

        var sampleIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "CanRead",
                    "Resource": "organisation:partition:iam:::account/100/service/*/sub-service"
                }
            ]
        };

        var processedIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "CanRead",
                    "ActionRegex": ["^CanRead$"],
                    "Resource": "organisation:partition:iam:::account/100/service/*/sub-service",
                    "ResourceRegex": [
                        "^organisation:partition:iam:::account/100/service/([0-9A-Za-z_]+/?)*/sub-service$"
                    ]
                }
            ]
        };

        expect(iam.processIamData(sampleIam)).to.deep.equal(processedIam);
    });



});


describe('During authorization checks', function(){

    describe('should fail to grant permission', function(){

        it('due to the action being limited', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["CanRead"],
                        "Resource": [
                            "organisation:partition:iam:::account/100/service/*/sub-service"
                        ]
                    }
                ]
            };


            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('organisation:partition:iam:::account/100/service/2/sub-service', 'CanUpdate',processedIam)).to.equal(false);
        });

        it('due to the account not matching the accounts permitted', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["CanRead"],
                        "Resource": [
                            "organisation:partition:iam:::account/100/service/*/sub-service"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('organisation:partition:iam:::account/101/service/2/sub-service', 'CanRead',processedIam)).to.equal(false);
        });



    });

    describe('should successfully to grant permission', function(){

        it('with a wildcard authorization resource', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["service:*"],
                        "Resource": [
                            "organisation:partition:service::608:*"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('organisation:partition:service:::search', 'service:CanRead',processedIam)).to.equal(true);

            var result = iam.getActionCriteria('service:CanRead', iam.processIamData(sampleIam));

            //console.log(result);


        });


        it('with a wildcard IAM resource', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["service:CanRead"],
                        "Resource": [
                            "organisation:partition:iam::100:resource/*"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('organisation:partition:iam::100:resource/2', 'service:CanRead',processedIam)).to.equal(true);
        });


        it('with a fixed resource', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["CanRead"],
                        "Resource": [
                            "organisation:partition:iam::100:resource/2"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('organisation:partition:iam::100:resource/2', 'CanRead',processedIam)).to.equal(true);
        });

        it('with a root level resource', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["CanRead"],
                        "Resource": [
                            "organisation:partition:iam::100:*"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('organisation:partition:iam::100:resource/2', 'CanRead',processedIam)).to.equal(true);
        });

        it('with a root level resource and a wildcard at the end of the action.', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["Can*"],
                        "Resource": [
                            "organisation:partition:iam::100:*"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('organisation:partition:iam::100:resource/2', 'CanRead',processedIam)).to.equal(true);
        });

        it('with a root level resource and a wildcard at the start of the action.', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["*Read"],
                        "Resource": [
                            "organisation:partition:iam::100:*"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('organisation:partition:iam::100:resource/2', 'CanRead',processedIam)).to.equal(true);
        });

        it('with a root level resource and a wildcard at the start and end of the action.', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["*an*"],
                        "Resource": [
                            "organisation:partition:iam::100:*"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('organisation:partition:iam::100:resource/2', 'CanRead',processedIam)).to.equal(true);
        });

        it('with a root level resource and a wildcard at the start of the action with multiple actions.', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["*Read", "CanView"],
                        "Resource": [
                            "organisation:partition:iam::100:*"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('organisation:partition:iam::100:resource/2', 'CanRead',processedIam)).to.equal(true);
        });

        it('with multiple root level resource and a wildcard at the start of the action with multiple actions.', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["*Read", "CanView"],
                        "Resource": [
                            "organisation:partition:iam::100:*",
                            "organisation:partition:iam::200:*"
                        ]
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('organisation:partition:iam::100:resource/2', 'CanRead',processedIam)).to.equal(true);
            expect(iam.authorize('organisation:partition:iam::200:resource/2', 'CanView',processedIam)).to.equal(true);
        });


    });

    describe('should successfully to deny permission', function(){

        it('with a wildcard resource', function(){

            var sampleIam = {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "organisation:partition:iam::100:*"
                    },
                    {
                        "Effect": "Deny",
                        "Action": "CanRead",
                        "Resource": "organisation:partition:iam::100:resource/2"
                    }
                ]
            };

            var processedIam = iam.processIamData(sampleIam);

            expect(iam.authorize('organisation:partition:iam::100:resource/2', 'CanRead',processedIam)).to.equal(false);
        });


    });

});

describe('During gathering the action criteria', function(){

    it('should allow with general wildcards.', function(){
        var sampleIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["service:*"],
                    "Resource": [
                        "organisation:partition:service::100:*"
                    ]
                }
            ]
        };

        var result = iam.getActionCriteria('service:SearchResults', iam.processIamData(sampleIam));

        expect(result).to.have.all.keys(['100']);
        expect(result[100].Must).to.have.length(0);
        expect(result[100].MustNot).to.have.length(0);

    });

    it('should allow with an account level wildcard and a single resource deny.', function(){
        var sampleIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["service:*"],
                    "Resource": [
                        "organisation:partition:service::100:*"
                    ]
                },
                {
                    "Effect": "Deny",
                    "Action": ["service:*"],
                    "Resource": [
                        "organisation:partition:service::100:resource/1500"
                    ]
                }
            ]
        };

        var result = iam.getActionCriteria('service:SearchResults', iam.processIamData(sampleIam));

        expect(result).to.have.all.keys(['100']);
        expect(result[100].Must).to.have.length(0);
        expect(result[100].MustNot).to.have.length(1);
        expect(result[100].MustNot[0]).to.deep.equal({ "type": "resource", "id": "1500" } );

    });

    it('should allow with multiple an account level wildcards and a single resource deny.', function(){
        var sampleIam = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["service:*"],
                    "Resource": [
                        "organisation:partition:service::100:*",
                        "organisation:partition:service::200:*"
                    ]
                },
                {
                    "Effect": "Deny",
                    "Action": ["service:*"],
                    "Resource": [
                        "organisation:partition:service::100:resource/1500"
                    ]
                }
            ]
        };

        var result = iam.getActionCriteria('service:SearchResults', iam.processIamData(sampleIam));

        expect(result).to.have.all.keys(['100','200']);
        expect(result[100].Must).to.have.length(0);
        expect(result[100].MustNot).to.have.length(1);
        expect(result[100].MustNot[0]).to.deep.equal({ "type": "resource", "id": "1500" } );

        expect(result[200].Must).to.have.length(0);
        expect(result[200].MustNot).to.have.length(0);

    });


});
