var stompClient = null;
var showLog = false;

function connect() {
    var socket = new SockJS('/gs-guide-websocket');
    stompClient = Stomp.over(socket);
    stompClient.connect({}, function (frame) {
        console.log('Connected: ' + frame);
        stompClient.subscribe('/topic/click', function (greeting) {
            var ct = JSON.parse(greeting.body).count;
            $("button").text("Click Me " + ct + "x");
            if (showLog) {
              showGreeting(JSON.parse(greeting.body).content);
            }
        });
        showLog=true;
        stompClient.send("/app/click", {}, JSON.stringify({'count': 0, 'isInit': false}));
    });
}

function disconnect() {
    if (stompClient !== null) {
        stompClient.disconnect();
    }
    console.log("Disconnected");
}

function sendName() {
  var str = $("button").text();
  var pattern = /\d+/;
  var result = pattern.exec(str);
  var ct = parseInt(result);
  stompClient.send("/app/click", {}, JSON.stringify({'count': ct, 'isInit': true}));
}

function showGreeting(message) {
  $("#greetings").html("");
  $.each(message, function( index, value ) {
    $("#greetings").append("<tr><td>" + value + "</td></tr>");
  });
}

$(function () {
  connect();
  //init();

  $(window).bind('beforeunload', function(){
    disconnect();
  });

  $( "button" ).click(function() { sendName(); });
});
