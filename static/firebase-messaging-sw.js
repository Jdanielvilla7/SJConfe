importScripts('https://www.gstatic.com/firebasejs/10.12.2/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.12.2/firebase-messaging-compat.js');


firebase.initializeApp({
  apiKey: "AIzaSyC5jWT-1bUL_IjHLs7xpTdcKRNLZpbn-oM",
  authDomain: "sjconfe-e9f07.firebaseapp.com",
  projectId: "sjconfe-e9f07",
  storageBucket: "jconfe-e9f07.firebasestorage.app",
  messagingSenderId: "595583890328",
  appId: "1:595583890328:web:14598da6a5be3493f531ed"
});

const messaging = firebase.messaging();

messaging.onBackgroundMessage(function(payload) {
  const { title, body } = payload.notification;
  self.registration.showNotification(title, { body });
});
