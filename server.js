require('newrelic');
/**
 * Module dependencies.
 */
var express = require('express')
    , expressSession = require('express-session')
    , http = require('http')
    , https = require('https')
    , cors = require('cors')
    , fs = require('fs')
    , os = require('os')
    , path = require('path');
var config = require('config');
var bodyParser = require('body-parser');
var methodOverride = require('method-override');
var basicAuth = require('./controller/basicAuth');
var favicon = require('serve-favicon');
var cookieParser = require('cookie-parser');
var expressLogger = require('morgan');
var errorHandler = require('errorhandler');
var RedisStore = require('connect-redis')(expressSession);
var Logger = require('./controller/Logger');
/*
 * create a database connection
 */
try {
    var dbHealper = require('./store/dbhealper');
    var db = dbHealper.connect(function () {
        //sync all Exigo users
        //ExigoUsersSync.startSync();
        //var newApiAuth = new ApiAuth({ name: "Saint Swipe App", authKey: AppUtil.guid() });
        /*newApiAuth.save(function (err,apiauth) {
         if(err){
         console.log('fail to save the api auth');
         }else{
         console.log('new api auth saved ',apiauth);
         }
         });*/
    });
} catch (err) {
    Logger.info('Connction fail to db with err %s', err.message);
}

/**
 *  Local Module dependencies.
 */
var routes = require('./routes')
    , user = require('./routes/userlist')
    , CustomerImage = require('./routes/CustomerImage')
    , webBroadcastApis = require('./routes/webBroadcastApis')
    , saveaudio = require('./routes/sendmessage')
    , sendVideoMessageRoute = require('./routes/sendVideoMessage')
    , broadcastMessage = require('./routes/broadcastMessage')
    , webBroadcastMessage = require('./routes/webBroadcastMessage')
    , webBroadcastMessage2 = require('./routes/webBroadcastMessage2')
    , sendTextMessage = require('./routes/sendTextMessage')
    , VendorEvent = require('./routes/vendorEvent')
    , messageList = require('./routes/messageslist')
    , login = require('./routes/login')
    , friendRequest = require('./routes/friend_request')
    , rankRoute = require('./routes/rankRoute')
    , chatManager = require('./routes/createChat')
    , sendPictureMessage = require('./routes/sendPictureMessage')
    , registerDevice = require('./routes/registerDevice')
    , DeviceUpdate = require('./routes/deviceUpdate')
    , NotificationGetter = require('./routes/getNotification')
    , users = require('./routes/users')
    , feedback = require('./routes/feedback')
    , leadRoute = require('./routes/leadRoute')
    , OfficeRoute = require('./routes/officeRoute')
    , LocaleRoute = require('./routes/locale')
    , CustomCSSRoute = require('./routes/CustomCSS')
    , resourceRoute = require('./routes/resourceRoute')
    , shareRoute = require('./routes/shareRoute')
    , calendarEventRoute = require('./routes/calendarEventRoute')
    , qrCodeRoute = require('./routes/qrCodeRoute');

var RedisClientManager = require("./controller/RedisClientManager");
var ExigoUsersSync = require('./controller/ExigoUsersSync');
var FileManager = require('./controller/FileManager');

var AppUtil = require('./controller/AppUtil');
var DeviceToken = require('./store/deviceToken').DeviceToken;
var ApiAuth = require('./store/apiAuth').ApiAuth;
var Company = require('./store/company').Company;

console.log('yes the env is ', AppUtil.getNodeEnv());

var app = express();
var multer = require('multer');
var upload = multer({
    dest: __dirname + '/temp/files',
    limits: {fieldSize: 300 * 1024 * 1024, fieldNameSize: 300 * 1024 * 1024}
});

var corsOptions = {
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
};

/**
 * make sure to use https
 * @param req
 * @param res
 * @param next
 * @returns {*}
 */
function requireHTTPS(req, res, next) {
    /*if (req.headers["x-forwarded-proto"] === "https"){
        return next();
     }else{
     if(req.url=='/index.html' || req.url=='/') {
        fs.readFile('./public/test/index.html',function(err,data){
        res.end(data);
     });
     }else {
        res.writeHead(301, {"Location": "https://" + req.headers['host'] + req.url});
        res.end();
        res.redirect("https://" + req.headers.host + req.url);
     }
     }*/
    if (req.url == '/index.html' || req.url == '/') {
        fs.readFile('./public/test/index.html', function (err, data) {
            res.end(data);
        });
    } else {
        return next();
    }
    /*if (!req.secure){
     if(req.url=='/index.html' || req.url=='/') {
     fs.readFile('./public/test/index.html',function(err,data){
     res.end(data);
     });
     }else {
     res.writeHead(301, {"Location": "https://" + req.headers['host'] + req.url});
     res.end();
     //res.redirect("https://" + req.headers.host + req.url);
     }
     }else{
     return next();
     }*/
}

var port = AppUtil.normalizePort(process.env.PORT || '3000');
//config yo
app.set('port', process.env.PORT || port);
// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(expressLogger('dev'));
app.use(favicon(__dirname + '/public/images/favicon.ico'));
var bodyParserOptions = {
    extended: true,
    parameterLimit: 50000000,
    limit: '300mb'
};
app.use(bodyParser.json(bodyParserOptions));
app.use(bodyParser.urlencoded(bodyParserOptions));

if (os.hostname() == 'Anirudhs-iMac.local' || os.hostname() == 'Max'/*&& AppUtil.getNodeEnv() !=='production'*/) {
    console.log('yo its my local machine ');
    app.use(cookieParser('tmlink#m1a1he1s1h%a1a1in1***12j2e2f2f'));
    app.use(expressSession({secret: 'tmlnk#m1a1he1s1h%a1a1in1***12j2e2f2f', resave: true, saveUninitialized: true}));
} else {
    app.use(requireHTTPS);
    app.use(cookieParser('tmlink#m1a1he1s1h%a1a1in1***12j2e2f2f'));
    app.use(expressSession({
        secret: 'tmlink#m1a1he1s1h%a1a1in1***12j2e2f2f',
        resave: true,
        saveUninitialized: true,
        store: new RedisStore({client: RedisClientManager.store})
    }));
}
//use error handler for dev
if (AppUtil.getNodeEnv() === 'development') {
    app.use(errorHandler());
}
app.use(methodOverride());
app.use(cors(corsOptions));
app.use(express.static(path.join(__dirname, 'public')));


/**
 * ------------------------------------------------------------------------
 *                            SERVER ADMIN ROUTS
 * ------------------------------------------------------------------------
 */

/**
 * A middleware to store page title in session title from hostname
 * @param req
 * @param res
 * @param next
 */
var pageTitleByOrigin = function (req, res, next) {
    var hostName = req.hostname;
    // var hostName = 'stream.teamlinkapp.com';
    console.log('hostname is ', hostName);
    var hostNameFields = hostName.split('.');
    if (hostName.endsWith('teamlinkapp.com')) {
        var company = hostNameFields[0];
        if (!AppUtil.isStringEmpty(company)) {
            var searchRag = new RegExp("^" + company + "$", 'i');
            var query = {company: searchRag};
            Company.findOne(query, 'name', function (err, companyConf) {
                if (err) {
                    Logger.error("error company config by company name", err);
                    res.send(500);
                } else if (companyConf) {
                    if (companyConf.name) {
                        req.session.companyName = companyConf.name;
                    } else {
                        req.session.companyName = '';
                    }
                }
                next();
            });
        } else {
            req.session.companyName = '';
            next();
        }
    } else {
        next();
    }

};

var companyMediaUpload = upload.fields([{name: 'loginLogo', maxCount: 1}, {name: 'primaryLogo', maxCount: 1}]);

var admin = require('./routes/admin');
var adminLogin = require('./routes/admin/login');
var usersList = require('./routes/admin/usersList');
var usersDevice = require('./routes/admin/userDevice');
var logger = require('./routes/admin/logger');
var enroller = require('./routes/admin/enroller');
var password = require('./routes/admin/password');
var companyNotificaion = require('./routes/admin/companyNotificaion');
var companyConf = require('./routes/admin/companyConf');
var stats = require('./routes/admin/stats');
var feedbackManager = require('./routes/admin/feedback');
var faqs = require('./routes/faqs');
var faqsManager = require('./routes/admin/faqs');
var devToolsApis = require('./routes/admin/devTool');
var localeAdmin = require('./routes/admin/localeAdmin');
var webBroadcastAdmin = require('./routes/admin/webBroadcast');
var resourcesAdmin = require('./routes/admin/resources');
var shareAdmin = require('./routes/admin/share');
var eventsAdmin = require('./routes/admin/calendarEvent');
//var blockUserManager = require('./routes/admin/blockUserManager');

//ajax call
app.post('/admin/ActionLogin', adminLogin.actionLogin);
app.post('/admin/enrollUser', adminLogin.authenticate, upload.single('image'), enroller.enrollUser);
app.post('/admin/saveNewPassword', adminLogin.authenticate, password.saveNewPassword);
app.post('/admin/blockUser', adminLogin.authenticate, usersList.blockUser);
app.post('/admin/allowTest', adminLogin.authenticate, usersList.allowTest);
app.post('/admin/createBroadcastGroup', adminLogin.authenticate, usersList.createBroadcastGroup);
app.post('/admin/broadcastNotification', adminLogin.authenticate, companyNotificaion.broadcastNotification);
app.post('/admin/updateNotificationExpiry', adminLogin.authenticate, companyNotificaion.updateNotificationExpiry);
app.get('/admin/getMessagesList', companyNotificaion.getMessagesList);
app.post('/admin/deleteNotification', companyNotificaion.deleteNotification);
app.post('/admin/findDevice', usersDevice.findDevice);
app.post('/admin/deleteDevice', adminLogin.authenticate, usersDevice.deleteDevice);
app.post('/admin/saveFaq', adminLogin.authenticate, faqsManager.saveFaq);
app.post('/admin/changeCredentials', adminLogin.authenticate, companyConf.changeCredentials);
app.post('/admin/changeConfig', adminLogin.authenticate, companyMediaUpload, companyConf.changeConfig);
app.post('/admin/changeDBConfig', adminLogin.authenticate, companyConf.changeDBConfig);

app.post('/admin/locale/importKeyValueFromJsonFile', adminLogin.authenticate, upload.single('file'), localeAdmin.importKeyValueFromJsonFile);
app.post('/admin/locale/importTranslationFromJson', adminLogin.authenticate, upload.single('file'), localeAdmin.importTranslationFromJson);
//app.post('/admin/locale/addKeyValue', localeAdmin.addKeyValue);
//app.post('/admin/locale/updateKeyValue', localeAdmin.updateKeyValue);
app.post('/admin/locale/deleteKeyValue', adminLogin.authenticate, localeAdmin.deleteKeyValue);
app.post('/admin/locale/saveKeyValue', adminLogin.authenticate, localeAdmin.saveKeyValue);
app.get('/admin/locale/getKeyValues', adminLogin.authenticate, localeAdmin.getKeyValues);
app.get('/admin/locale/getKeyValues/:id', adminLogin.authenticate, localeAdmin.getKeyValues);

app.get('/admin/locale/getLanguages', adminLogin.authenticate, LocaleRoute.getLanguages);
app.get('/admin/locale/getAllLanguageCodes', adminLogin.authenticate, localeAdmin.getAllLanguageCodes);

//broadcast admin apis
app.get('/admin/webBroadcast/getWebBroadCastList', adminLogin.authenticate, webBroadcastAdmin.getWebBroadCastList);
app.get('/admin/webBroadcast/exportWebBroadCastListToCsv', adminLogin.authenticate, webBroadcastAdmin.exportWebBroadCastListToCsv);

//RESOURCES routes
app.post('/admin/saveResource', adminLogin.authenticate, resourcesAdmin.saveResource);
app.post('/admin/saveCategory', adminLogin.authenticate, resourcesAdmin.saveCategory);
app.post('/admin/deleteCategory', adminLogin.authenticate, resourcesAdmin.deleteCategory);
app.post('/admin/saveGetStartedResource', resourcesAdmin.saveGetStartedResource);
app.get('/admin/deleteResource', adminLogin.authenticate, resourcesAdmin.deleteByID);
app.get('/admin/getResourceByID', adminLogin.authenticate, resourcesAdmin.getResourceByID);
app.get('/admin/getStartedResource', adminLogin.authenticate, resourcesAdmin.getStartedResource);
app.get('/admin/deleteGetStartedResource', adminLogin.authenticate, resourcesAdmin.deleteGetStartedResource);
app.get('/admin/resourcesList', adminLogin.authenticate, resourcesAdmin.viewResourcesList);
app.get('/admin/createResource', adminLogin.authenticate, resourcesAdmin.createResourceForm);
app.get('/admin/gettingStarted', adminLogin.authenticate, resourcesAdmin.gettingStartedForm);

//Share routes
app.get('/admin/sharesList', adminLogin.authenticate, shareAdmin.viewSharesList);
app.get('/admin/createShareDetail', adminLogin.authenticate, shareAdmin.createShareForm);
app.get('/admin/getShareDetailByID', adminLogin.authenticate, shareAdmin.getShareDetailByID);
app.post('/admin/saveShareDetail', adminLogin.authenticate, shareAdmin.saveShareDetail);
app.post('/admin/deleteShareCategory', adminLogin.authenticate, shareAdmin.deleteCategory);
app.post('/admin/saveShareCategory', adminLogin.authenticate, shareAdmin.saveCategory);
app.get('/admin/deleteShareDetail', adminLogin.authenticate, shareAdmin.deleteByID);

//Events routes
app.get('/admin/eventsList', adminLogin.authenticate, eventsAdmin.viewEventList);
app.get('/admin/createEvent', adminLogin.authenticate, eventsAdmin.createEventForm);
app.get('/admin/getEventList', eventsAdmin.getEventList);
app.get('/admin/deleteEventByID', eventsAdmin.deleteEventByID);
app.get('/admin/getEventByID', eventsAdmin.getEventByID);
app.post('/admin/saveEvent', eventsAdmin.saveEvent);

//ajax get
app.get('/admin/getServerEnv', admin.getServerEnv);
app.get('/admin/getUserMessagecount', adminLogin.authenticate, usersList.getUserSentMessageCount);
app.get('/admin/findUser', usersList.findUser);
app.get('/admin/getUserDevies', usersList.getUserDevies);
app.get('/admin/getUsersList', usersList.getUsersList);
app.get('/admin/getBlockedUsers', usersList.getBlockedUsers);
app.get('/admin/getUserActivityLog', usersList.getUserActivityLog);
app.get('/admin/getLogs', adminLogin.authenticate, logger.getLogs);
app.get('/admin/getMessageStatics', adminLogin.authenticate, stats.getMessageStatics);
app.get('/admin/validateAdminUsername', enroller.validateAdminUsername);
app.get('/admin/validateSalesLinkManagerEmail', enroller.validateSalesLinkManagerEmail);
app.get('/admin/validateAdminEnrollerID', enroller.validateAdminEnrollerID);
app.get('/admin/getFeedbackList', feedbackManager.getFeedbackList);
app.get('/admin/getFeedbackListByCompany', feedbackManager.getFeedbackListByCompany);
app.get('/admin/markFeedbackAsRead', feedbackManager.markAsRead);
app.get('/admin/deleteFeedback', feedbackManager.deleteByID);
app.get('/admin/getUserFilterOptionsMap', companyNotificaion.getUserFilterOptionsMap);
app.get('/admin/getCountryRegions', companyNotificaion.getCountryRegions);
app.get('/admin/getCompaniesList', companyNotificaion.getCompaniesList);
app.get('/admin/getCompaniesListDetail', adminLogin.authenticate, companyConf.getCompaniesList);
app.get('/admin/getFaqsList', faqsManager.getFaqsList);
app.get('/admin/deleteFaq', adminLogin.authenticate, faqsManager.deleteByID);
app.get('/admin/getCustomerTypes', companyConf.getCustomerTypes);
app.get('/admin/getAllTreeTypes', companyConf.getTreeTypesAdmin);
app.get('/admin/validateDefaultEnrollerID', companyConf.validateDefaultEnrollerID);
app.get('/admin/getResourceList', resourcesAdmin.getResourcesList);
app.get('/admin/getCategoryList', resourcesAdmin.getCategoryList);
app.get('/admin/getShareList', shareAdmin.getShareList);
app.get('/admin/getShareCategoryList', shareAdmin.getCategoryList);

//web pages
app.get('/admin/login', pageTitleByOrigin, adminLogin.login);
app.get('/admin/logout', adminLogin.logout);
app.get('/admin', adminLogin.authenticate, admin.home);
app.get('/admin/home', adminLogin.authenticate, admin.home);
app.get('/admin/activeUsersCount', adminLogin.authenticate, admin.activeUsersCount);
app.get('/admin/onlineUsersCount', adminLogin.authenticate, admin.onlineUsersCount);
app.get('/admin/feedBacksCount', adminLogin.authenticate, admin.feedBacksCount);
app.get('/admin/messagesCount', adminLogin.authenticate, admin.messagesCount);
app.get('/admin/users', adminLogin.authenticate, usersList.viewUsersList);
app.get('/admin/devices', adminLogin.authenticate, usersDevice.manageDevice);
app.get('/admin/enrollTestUser', adminLogin.authenticate, enroller.showEnrollForm);
app.get('/admin/enrollManager', adminLogin.authenticate, enroller.showManagerForm);
app.get('/admin/enrollUser', adminLogin.authenticate, enroller.showUserForm);
app.get('/admin/enrollAdmin', adminLogin.authenticate, enroller.showEnrollAdminForm);
app.get('/admin/createBroadcast', adminLogin.authenticate, enroller.createBroadcast);
app.get('/admin/blockUser', adminLogin.authenticate, usersList.viewBlockUser);
app.get('/admin/viewUser', adminLogin.authenticate, usersList.viewUser);
app.get('/admin/viewStats', adminLogin.authenticate, stats.viewStats);
app.get('/admin/viewUser', adminLogin.authenticate, usersList.viewUser);
app.get('/admin/changePassword', adminLogin.authenticate, password.chnangePassword);
app.get('/admin/sendNotificaion', adminLogin.authenticate, companyNotificaion.sendNotificaion);
app.get('/admin/messageList', adminLogin.authenticate, companyNotificaion.viewMessageList);
app.get('/admin/logs', adminLogin.authenticate, logger.showLogs);
app.get('/admin/feedback', adminLogin.authenticate, feedbackManager.listFeedback);
app.get('/admin/viewFeedback', adminLogin.authenticate, feedbackManager.viewFeedback);
app.get('/admin/createFaq', adminLogin.authenticate, faqsManager.createFaq);
app.get('/admin/editFaq', adminLogin.authenticate, faqsManager.editFaq);
app.get('/admin/listFaqs', adminLogin.authenticate, faqsManager.listFaqs);
app.get('/admin/profile', adminLogin.authenticate, admin.profile);
app.get('/admin/companies', adminLogin.authenticate, companyConf.viewCompanyList);
app.get('/admin/changeConfiguration', adminLogin.authenticate, companyConf.changeConfigurationForm);
app.get('/admin/getCompanyConfigByCompany', companyConf.getCompanyConfigByCompany);

app.get('/admin/manageLocale', adminLogin.authenticate, localeAdmin.manageLocale);
app.get('/admin/importLocaleByFile', adminLogin.authenticate, localeAdmin.importLocaleByFile);
app.get('/admin/broadcastList', adminLogin.authenticate, webBroadcastAdmin.viewWebBroadCastList);

app.get('/faqs/', faqs.faqAndroid);
app.get('/faqs/android', faqs.faqAndroid);
app.get('/faqs/ios', faqs.faqIOS);
app.get('/faqs/chrome', faqs.faqChromeApp);


/**
 * ------------------------------------------------------------------------
 *                        SERVER API ROUTS
 * ------------------------------------------------------------------------
 */

/**
 * A middleware to get the company name from hostname and pass it for theme CSS
 * @param req
 * @param res
 * @param next
 */
var companyNameByOrigin = function (req, res, next) {
    var hostName = req.hostname;
    console.log('hostname is ', hostName);
    var hostNameFields = hostName.split('.');
    if (hostName.endsWith('teamlinkapp.com')) {
        var company = hostNameFields[0];
        req.params.company = company;
    }
    next();
};

var CompanyApiRequest = require("./controller/CompanyApiRequest");
/**
 * A middleware to check the company key from request and assign the requested api client to request object
 * @param req
 * @param res
 * @param next
 */
var companyApiClientChecker = function (req, res, next) {
    var companyKey = req.param('companyKey');// || config.get('DEFAULT_COMPANY_KEY');
    var company = req.param('company'); // use can send comapny name for some request
    if (AppUtil.isObjectId(companyKey)) {
        CompanyApiRequest.getRequestClient(companyKey, function (err, client) {
            if (err) {
                Logger.info('Error :: ', err);
                res.send(500, err.message);
            } else if (client) {
                req.companyApiClient = client;
                next();
            } else {
                res.send(401, "Invalid company key");
            }
        });
    } else if (!AppUtil.isStringEmpty(company)) {
        var searchRag = new RegExp("^" + company + "$", 'i');
        var query = {$or: [{company: searchRag}, {name: searchRag}]};
        Company.findOne(query, function (err, companyConf) {
            if (err) {
                Logger.error("error Company.findOne companyApiClientChecker server.js", err);
                res.send(500);
            } else if (companyConf) {
                companyKey = companyConf._id.toString();
                CompanyApiRequest.getRequestClient(companyKey, function (err, client) {
                    if (err) {
                        Logger.info('Error :: ', err);
                        res.send(500, err.message);
                    } else if (client) {
                        req.companyApiClient = client;
                        next();
                    } else {
                        res.send(401, "Invalid company key");
                    }
                });
            } else {
                res.send(401, 'No such company setup found.');
            }
        });
    } else {
        res.send(401, "Invalid company key not a objectId");
    }
};
//User validation
var auth = basicAuth(function (userId, authToken, func) {
    DeviceToken.findById(authToken).lean().exec(function (err, device) {
        func(err, device && device.userID.toString() == userId ? device : undefined);
    });
}, 'Api Access Authentication Needed.');
var extApiAuth = basicAuth(function (keyID, authKey, func) {
    ApiAuth.findById(keyID, function (err, device) {
        func(err, device && device.authKey === authKey ? device : undefined);
    });
}, 'Api Access Authentication Needed.');
app.get('/', routes.index);


var chatS = require('./controller/ChatService');
app.post('/setDeviceToOffline', chatS.setDeviceToOffline);

var logMediaUpload = upload.fields([{name: 'images', maxCount: 3}, {name: 'logFile', maxCount: 1}]);

app.get('/getCustomerImage', companyApiClientChecker, CustomerImage.getCustomerImage);
app.get('/searchContact', auth, companyApiClientChecker, user.searchContact);
app.post('/searchContact', auth, companyApiClientChecker, user.searchContact);//for some reason we users need it to be post
app.get('/getContacts', auth, companyApiClientChecker, user.list);
app.get('/isUserOnline', auth, companyApiClientChecker, user.getUserOnlineStatus);
app.get('/getActiveChatUsers', auth, companyApiClientChecker, user.getActiveChatUsers);
app.get('/getActiveChatUsersWithLastMessageId', auth, companyApiClientChecker, user.getActiveChatUsersWithLastMessageId);
app.get('/getRostersUpdate', auth, companyApiClientChecker, user.getRostersUpdate);
app.post('/blockContact', auth, companyApiClientChecker, user.blockContact);
app.post('/deleteContact', auth, companyApiClientChecker, user.deleteContact);

app.post('/changeProfileImage', upload.single('image'), auth, companyApiClientChecker, user.changeProfileImage);

app.get('/messageslist', auth, companyApiClientChecker, messageList.messageList);
app.get('/getMessageList', auth, companyApiClientChecker, messageList.messageList);
app.get('/getPendingListener', auth, companyApiClientChecker, messageList.getPendingListener);
app.get('/getPendingMessages', auth, companyApiClientChecker, messageList.getPendingMessages);
app.get('/getPendingMessageAcks', auth, companyApiClientChecker, messageList.getPendingMessageAcks);
app.get('/getMessagesStatus', auth, companyApiClientChecker, messageList.getMessagesStatus);
app.post('/resetPendingMessageCount', auth, companyApiClientChecker, messageList.resetPendingMessageCount);


app.get('/getPendingRequests', auth, companyApiClientChecker, friendRequest.getAllPendingRequests);
app.get('/getPendingRequestsCount', auth, companyApiClientChecker, friendRequest.getPendingRequestsCount);
app.post('/sendRequest', auth, companyApiClientChecker, friendRequest.sendRequest);
app.post('/sendContactRequest', auth, companyApiClientChecker, friendRequest.sendContactRequest);
app.post('/acceptRequest', auth, companyApiClientChecker, friendRequest.acceptFriendRequest);
app.post('/ignoreRequest', auth, companyApiClientChecker, friendRequest.ignoreRequest);
app.post('/inviteFriendByMail', auth, companyApiClientChecker, friendRequest.inviteFriendByMail);

//Ranks
app.get('/getRanks', auth, companyApiClientChecker, rankRoute.getRanks);

app.get('/getChatList', auth, companyApiClientChecker, chatManager.getChatList);
app.get('/getChatListWithOnlineStatus', auth, companyApiClientChecker, chatManager.getChatListWithOnlineStatus);
app.get('/getPersonalChatListWithOnlineStatus', auth, companyApiClientChecker, chatManager.getPersonalChatListWithOnlineStatus);
app.get('/getUnreadMessageCount', auth, companyApiClientChecker, chatManager.getUnreadMessageCountV2);
app.get('/getUnreadMessageCountV2', auth, companyApiClientChecker, chatManager.getUnreadMessageCountV2);
app.get('/getGroupImage', companyApiClientChecker, chatManager.getGroupImage);
app.post('/createChat', auth, companyApiClientChecker, chatManager.createChat);
app.post('/createGroupChat', auth, companyApiClientChecker, chatManager.createGroupChat);
app.post('/deleteChat', auth, companyApiClientChecker, chatManager.deleteChat);
app.post('/renameChat', auth, companyApiClientChecker, chatManager.renameChat);
app.post('/addPersonToChat', auth, companyApiClientChecker, chatManager.addPersonToChat);
app.post('/archiveChat', auth, companyApiClientChecker, chatManager.archiveChat);
app.post('/setNotificationEnabled', auth, companyApiClientChecker, chatManager.setNotificationEnabled);

app.post('/sendFeedback', auth, logMediaUpload, companyApiClientChecker, feedback.sendFeedback);
app.post('/sendPictureMessage', auth, companyApiClientChecker, upload.single('image'), sendPictureMessage.imageMessage);
app.post('/sendTextMessage', auth, companyApiClientChecker, sendTextMessage.sendText);
app.post('/sendmessage', upload.single('audio'), auth, companyApiClientChecker, saveaudio.saveaudio);
app.post('/sendVoiceMessage', upload.single('audio'), auth, companyApiClientChecker, saveaudio.saveaudio);
app.post('/sendVideoMessage', upload.single('video'), auth, companyApiClientChecker, sendVideoMessageRoute.sendVideo);
//var sendVoiceBroadcastUpload = upload.fields([{ name: 'audio', maxCount: 1 }, { name: 'image', maxCount: 1 }]);
app.post('/sendVoiceBroadcast', upload.single('audio'), auth, companyApiClientChecker, broadcastMessage.sendVoiceBroadcast);
app.post('/broadcastMessage', auth, upload.single('image'), companyApiClientChecker, webBroadcastMessage.broadcastMessage);
app.post('/login', login.doLogin);
app.post('/verifyEmail', companyApiClientChecker, login.verifyEmail);
app.post('/setupPassword', companyApiClientChecker, login.setupPassword);
app.post('/registerUser', auth, companyApiClientChecker, login.registerUser);
//app.post('/logout',login.doLogout);//not needed
app.post('/registerDevice', auth, companyApiClientChecker, registerDevice.registerToken);
app.post('/unRegisterDevice', auth, companyApiClientChecker, registerDevice.unRegisterToken);
app.post('/updateToken', auth, companyApiClientChecker, registerDevice.updateToken);

app.post('/updateBadge', auth, companyApiClientChecker, DeviceUpdate.updateBadge);
app.post('/markNotificationRead', auth, companyApiClientChecker, NotificationGetter.markNotificationRead);
app.get('/getNotification', auth, companyApiClientChecker, NotificationGetter.getNotification);
app.get('/getNotificationCount', auth, companyApiClientChecker, NotificationGetter.getNotificationCount);
app.get('/updateChatUserIdsRefrence', chatManager.updateChatUserIdsRefrence);

//LEADS routes
app.get('/leads/getLeadsList', auth, companyApiClientChecker, leadRoute.getLeadsList);
app.get('/leads/getLeadTimeLine', auth, companyApiClientChecker, leadRoute.getLeadTimeLine);
app.get('/leads/getLeadsNotesList', auth, companyApiClientChecker, leadRoute.getLeadsNotesList);
app.post('/leads/saveLead', auth, companyApiClientChecker, leadRoute.saveLead);
app.post('/leads/setLeadStatus', auth, companyApiClientChecker, leadRoute.setLeadStatus);
app.post('/leads/deleteLead', auth, companyApiClientChecker, leadRoute.deleteLead);
app.post('/leads/saveLeadNotes', auth, companyApiClientChecker, leadRoute.saveLeadNotes);
app.post('/leads/deleteLeadNotes', auth, companyApiClientChecker, leadRoute.deleteLeadNotes);
app.post('/leads/addLeadTimeLineEntry', auth, companyApiClientChecker, leadRoute.addLeadTimeLineEntry);
app.post('/leads/saveLeadFlowUp', auth, companyApiClientChecker, leadRoute.saveLeadFlowUp);

//CalendarEvent routes
app.get('/calendar/getEventList', companyApiClientChecker, calendarEventRoute.getEventList);
app.get('/calendar/getEventListByDateNumber', companyApiClientChecker, calendarEventRoute.getEventListByDateNumber);
app.get('/getEventListByMonth', companyApiClientChecker, calendarEventRoute.getEventListByMonth);

//QR Code routes
app.get('/qrcode/getQrCodeList', companyApiClientChecker, qrCodeRoute.getQrCodeList);
app.post('/qrcode/saveQrCodeDetail', upload.single('image'), companyApiClientChecker, qrCodeRoute.saveQrCodeDetail);
app.post('/qrcode/getQrCodeImgBase64', upload.single('image'), companyApiClientChecker, qrCodeRoute.getQrCodeImgBase64);
app.post('/qrcode/deleteQrCodeByID', companyApiClientChecker, qrCodeRoute.deleteQrCodeByID);

//Share routes
app.get('/shares/getShareList', companyApiClientChecker, shareRoute.getShareList);

//RESOURCES routes
app.get('/resources/getResourcesList', companyApiClientChecker, resourceRoute.getResourcesList);
app.get('/resources/getStartedResource', auth, companyApiClientChecker, resourceRoute.getStartedResource);

//LOCALE routes
app.get('/locale/string/:company/:langCode-:countryCode', LocaleRoute.getStringTranslation);
app.get('/locale/string/:company/:langCode', LocaleRoute.getStringTranslation);
app.get('/locale/exportStringTranslationFile', LocaleRoute.exportStringTranslationFile);
app.get('/locale/exportStringKeyValueFile', LocaleRoute.exportStringKeyValueFile);
app.get('/locale/getLanguages', LocaleRoute.getLanguages);
app.get('/custom_css/:company/theme.css', CustomCSSRoute.getCustomCssThemeVars);
app.get('/custom_css/theme.css', companyNameByOrigin, CustomCSSRoute.getCustomCssThemeVars);

app.get('/custom_image/:company/logo_primary.png', CustomCSSRoute.getCompanyLogoImage);
app.get('/custom_image/logo_primary.png', companyNameByOrigin, CustomCSSRoute.getCompanyLogoImage);
app.get('/custom_image/:company/login_logo.png', CustomCSSRoute.getLoginLogoImage);
app.get('/custom_image/login_logo.png', companyNameByOrigin, CustomCSSRoute.getLoginLogoImage);

//back office
app.get('/office/getBackOfficeSSOUrl', auth, companyApiClientChecker, OfficeRoute.getBackOfficeSSOUrl);

/**
 * ------------------------------------------------------------------------
 *                        SERVER EXT API ROUTS
 * ------------------------------------------------------------------------
 */
app.post('/ext/sendTextMessage', extApiAuth, companyApiClientChecker, sendTextMessage.sendText);
app.get('/ext/getMessageStaticsCompanyVise', extApiAuth, companyApiClientChecker, stats.getMessageStaticsCompanyVise);
app.post('/ext/removeOnlineWaitingMessages', extApiAuth, messageList.removeOnlineWaitingMessages);
app.get('/ext/getOnlineWaitingMessages', extApiAuth, companyApiClientChecker, messageList.getOnlineWaitingMessages);
app.get('/ext/getTotalMessagesCountCompanyVise', extApiAuth, companyApiClientChecker, stats.getTotalMessagesCountCompanyVise);
app.post('/ext/sendCustomVendorEvent', extApiAuth, companyApiClientChecker, VendorEvent.sendCustomVendorEvent);
//api to update user from exigo web
app.post('/ext/updateUser', extApiAuth, companyApiClientChecker, users.updateUser);
app.post('/ext/suspendUser', extApiAuth, companyApiClientChecker, users.suspendUser);
app.get('/ext/getSentMessageForBroadcast', extApiAuth, webBroadcastMessage2.getSentMessageForBroadcast);
app.post('/ext/broadcastMessage', extApiAuth, upload.single('image'), companyApiClientChecker, webBroadcastMessage2.broadcastMessage);
app.post('/ext/getPersonalChatListWithOnlineStatus', extApiAuth, companyApiClientChecker, chatManager.getPersonalChatListWithOnlineStatus);
app.post('/ext/deleteChatByID', extApiAuth, chatManager.deleteChatByID);
app.post('/ext/createChat', extApiAuth, companyApiClientChecker, chatManager.createChat);
app.post('/ext/deleteAccountRemoveChats', extApiAuth, companyApiClientChecker, chatManager.deleteAccountRemoveChats);
app.post('/ext/saveCompanyConf', extApiAuth, companyConf.saveCompany);//TODO add ext api auth
app.post('/ext/updateCompanyConfig', extApiAuth, companyConf.updateCompanyConfig);

app.post('/ext/unRegisterDevice', extApiAuth, companyApiClientChecker, registerDevice.unRegisterToken);
app.post('/ext/updateToken', extApiAuth, companyApiClientChecker, registerDevice.updateToken);
app.get('/ext/getWebBroadCastList', extApiAuth, webBroadcastApis.getWebBroadCastList);
app.post('/ext/getWebBroadCastList', extApiAuth, webBroadcastApis.getWebBroadCastList);
app.post('/ext/removeAllMessagesForBroadcast', extApiAuth, webBroadcastApis.removeAllMessagesForBroadcast);
app.post('/ext/clearRedisStoreAndRemoveBrowsers', extApiAuth, devToolsApis.clearRedisStoreAndRemoveBrowsers);
app.post('/ext/removeOfflineBrowsers', extApiAuth, devToolsApis.removeOfflineBrowsers);

app.post('/ext/fixEmptySNSARN', extApiAuth, devToolsApis.fixEmptyToken);
app.post('/ext/syncCompanyUsers', extApiAuth, companyApiClientChecker, devToolsApis.syncCompanyUsers);
app.post('/ext/clearRedisStore', extApiAuth, devToolsApis.clearRedisStore);
app.post('/ext/deleteCompanyChats', extApiAuth, companyApiClientChecker, devToolsApis.deleteCompanyChats);
app.post('/ext/deleteCompanyDetail', extApiAuth, companyApiClientChecker, devToolsApis.deleteCompanyDetail);
app.get('/ext/getNewDeleteToken', extApiAuth, companyApiClientChecker, devToolsApis.getNewDeleteToken);

app.post('/ext/getDuplicateUsersFor', extApiAuth, companyApiClientChecker, devToolsApis.getDuplicateUsersFor);
app.post('/ext/removeDuplicateChats', extApiAuth, devToolsApis.removeDuplicateChats);
app.get('/ext/getCustomerIds', extApiAuth, devToolsApis.getCustomerIds);
app.get('/ext/getOldMessageChatKeys', extApiAuth, devToolsApis.getOldMessageChatKeys);
app.post('/ext/updateOldMessageChatKeys', extApiAuth, devToolsApis.updateOldMessageChatKeys);
app.get('/ext/getNodeVersion', devToolsApis.getNodeVersion);
app.get('/ext/getMemoryUse', devToolsApis.getMemoryUse);
app.get('/ext/cacheUnreadMessageCountFirsTime', chatManager.cacheUnreadMessageCountFirsTime)

/**---------------------------------------------------*/
// catch 404 and forwarding to error handler
app.use(function (req, res, next) {
    var err = new Error('Not Found');
    err.status = 404;
    next(err);
});
// production error handler
// no stacktraces leaked to user
app.use(function (err, req, res, next) {
    if (err.status != 404 && err.status != 405) {
        Logger.warn("Inside error handler ");
        Logger.error('Inside error handler: ', err.message);
        Logger.error('Inside error handler: ', err.stack);
        Logger.error('Inside error handler: ', err);
        console.error("Inside error handler ", err);
    }
    res.status(err.status || 500);
    if (req.xhr) {
        res.send(err.status);
    } else {
        var title = "";
        switch (err.status) {
            case 404:
                title = "Not Found.";
                err.message = "The page you are looking for might have been removed, had its name changed, or unavailable.";
                break;
            case 405:
                title = "Method not allowed.";
                err.message = "The request not supported by current login user.";
                break;
            default:
                title = "Something went wrong.";
                if (err.message.length == 0) {
                    err.message = "We are fixing it!<br/> Please come back in a while.";
                }
                break;
        }
        if (req.session && req.session.user) {//if current session
            res.render('error', {
                message: err.message,
                status: err.status,
                title: title,
                page: 'notFound',
                User: req.session.user
            });
        } else {
            //show public error page
            res.render('errorPublic', {
                message: err.message,
                status: err.status,
                title: title,
                page: 'error'
            });
        }
    }
});
process.on('unhandledRejection', function (reason, promise) {
    console.error('Unhandled Rejection at:', reason.stack || reason)
    // Recommended: send the information to sentry.io
    // or whatever crash reporting service you use
});
process.on('uncaughtException', function (err) {
    console.error('we are inside exception here we are @@');
    console.error('Caught exception: ', err.message);
    console.error('Caught exception: ', err.message);
    console.error('Caught exception: ', err.stack);
    console.error('Caught exception: ', err);
    process.nextTick(function () {
        process.exit(1);
    });
});
module.exports = app;
/*--------------------------------------------------------------------------------------*/
/*				              Start the server                                           */
/*--------------------------------------------------------------------------------------*/
if (os.hostname() == config.get("PRIMARY_HOST_NAME")) {
    //schedule the sync and other application level process
    FileManager.scheduleDeleteOldFileFromCDNAndMessages();
}
//schedule temp file delete operation
FileManager.scheduleFileDelete(); //()startDeleteProcess

var chatService = require('./controller/ChatService').Server;
var SocketIOService = require('./controller/ChatService').SocketIOService;
chatService.listen(config.tcpPort, function () {
    Logger.info('Chat service is runnig on :' + config.tcpPort);
});
chatService.on('error', function (err) {
    if (err.code == 'EADDRINUSE') {
        Logger.info('Address in use, retrying...');
        setTimeout(function () {
            chatService.close();
            chatService.listen(config.tcpPort, function () {
                Logger.info('Chat service is running on :' + config.tcpPort);
            });
        }, 1000);
    }
    Logger.error('Error in chat service ' + err);
});

var read = fs.readFileSync;
var options = {
    cert: read('certs/cert.crt'),
    key: read('certs/key.key')
    //passphrase:'ws1dev123'
};

var httpPort = os.hostname() == 'Anirudhs-iMac.local' ? 3003 : 80;
var httpServer = http.createServer(app).listen(httpPort, function () {
    Logger.info('****************************************************************');
    Logger.info('---------- TeamLink server listening on port ' + httpPort + "-----------");
    Logger.info('****************************************************************');
});

var httpsPort = os.hostname() === 'Anirudhs-iMac.local' ? 3000 : 443;
var httpsServer = https.createServer(options, app).listen(httpsPort, function () {
    Logger.info('****************************************************************');
    Logger.info('---------- TeamLink server listening on port ' + httpsPort + "-----------");
    Logger.info('****************************************************************');
});

httpServer.timeout = 2400000;
httpsServer.timeout = 2400000;

httpsServer.maxHeadersCount = 0;//unlimited
httpsServer.on('error', function (err) {
    Logger.error('Error in http server ' + err.message);
});

var ioOptions = {
    'browser client minification': true,  // Send magnified client
    'browser client etag': true,          // Apply etag caching logic based on version number
    'browser client gzip': true,          // Gzip the file
    'browser client expires': true        // Adds Cache-Control: private, x-gzip-ok="", max-age=31536000 header
};

var io = require('socket.io')(httpsServer, ioOptions);
io.on('connection', SocketIOService);

var io2 = require('socket.io')(httpServer, ioOptions);
io2.on('connection', SocketIOService);