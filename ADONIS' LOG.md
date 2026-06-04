ADONIS' LOG



Week1: Treasury Module analysis (Caching, EOD Issues, Deals processing issues, UAT configuration and testing):

* *On top of the usual daily support his week was focused on diagnosing the treasury module which had been giving persistent issues on the Dealers side which was hindering the bank's treasury operations. The treasury module catches on the application level which requires period flashing of tmp and data files and restarting the module to ...'you know why'.*
* *On the other end the application constantly gave issues during end of day processes which required manual intervention to correct the application state in the database to allow all eod processes to complete successfully.* 
* *These and other unkowns affected the application's deals processing workflaws which hindered business. So we did investigations from our side but the issues persisted which required structured escalation to the vendor for support.* 
* *After thorough investigation with the vendor representative we surfaced a solution that adjusted the system database. The solution was first tested by the vendor, then we applied it to our secondary uat test sandbox for testing with the dealers team.*
* *The solution required the latest data dump from the live environment which resets the uat sandbox which in turn required me to configure the environment endpoints, data sources and the application stack including Treasury.* 
* *Configuration was smooth for the other modules but treasury presented issues making the application session handover form the ARX auth module to the treasury module point to the wrong url (the primary test environment) even with the database configs intact*
* *After investigating I realized that the issue was happening on the application level configs; the .war config.*
* *To narrow it down to detail I searched for the exact url the system way pointing to which took me to the exact misconfigured variable. The solution was simple, to change it to the correct one.*
* *I then gave the dealers access to the environment with clone accounts from the production environment.*
* *Testing faced a lot of hiccups with a bunch of features failed and needed to be fixed as we go.* 





Week2: Mobile Banking Analysis USSD issues (research, log diagnostics, dependency mapping, root cause diagnosis, network, vpn), Unable to access (MB mobile phone or number change)

* *On top of the usual stuff. I found myself in the middle of the persistent Mobile Banking issues particularly the USSD service availability.*
* *USSD is one of the most used services and channels as it presents a high level of convenience for clients as compared to other services. this is because the ussd \*\* code is not technically demanding to them...even without a smartphone you can access your money. This means that downtime for this service is unacceptable. when the service is compromised it presents a very high risk.*
* *After constant monitoring and runtime log analysis I realized that the investigations surfaced the fact that most of the persisting issues were on the channel/network level rather than the application itself. On occurrence of an incident we're bound to stop the restart the service and its adapter when the log is not moving.*
* *So to pinpoint the issue I monitored the log and realized that the service would be completely functional but the channel disconnects. When this happens the service closes all current sessions all at once with no intermediate transaction traces or login attempts.* 
* *Planned and designed the Nexus feature for SentinelOps for 'You know all about this <Nexus, nexus light, txn-mobile-ussd as the first focus for diagnostic... structure the knowledge properly for the log...*



Week3: UAT Dump, reconfiguration, eod marathon, eod failure, apis, webservices. New Postilion configuration; Migration or roles form Old postilion

* 



Week4: Fortipam introduction, onboarding and training, Econet airtime, bank to wallet (Vendor services), Netone airtime, one money integration.

* 



Week5: Flexidocs \& Selfservice deployment on windows server ++ Production deployment failure, rollback, diagnostics and redeployment.

* 

