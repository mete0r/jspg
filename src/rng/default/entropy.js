/* Collect entropy from mouse motion and key press events
 * Note that this is coded to work with either DOM2 or Internet Explorer
 * style events.
 * We don't use every successive mouse movement event.
 * Instead, we use some bits from random() to determine how many
 * subsequent mouse movements we ignore before capturing the next one.
 * rc4 is used as a mixing function for the captured mouse events.  
 *
 * mouse motion event code originally from John Walker
 * key press timing code thanks to Nigel Johnstone
 */

function Entropy() {

  var DOM2EventModel = {
    'install': function(eventtype, f) {
      document.addEventListener(eventtype, f, false);
    },
    'uninstall': function(eventtype, f) {
      document.removeEventListener(eventtype, f, false);
    },
    'eventtypes': {
      'keypress': 'keypress',
      'mousemove': 'mousemove',
    }
  };

  var IE5EventModel = {
    'install': function(eventtype, f) {
      document.attachEvent(eventtype, f);
    },
    'uninstall': function(eventtype, f) {
      document.detachEvent(eventtype, f);
    },
    'eventtypes': {
      'keypress': 'onkeypress',
      'mousemove': 'onmousemove',
    }
  };

  var Netscape4EventModel = {
    'install': function(eventtype, f) {
      document.captureEvents(eventtype.event);
      eventtype.setter(f);
    },
    'uninstall': function(eventtype, f) {
      document.ReleaseEvents(eventtype.event);
      eventtype.setter(null);
    },
    'eventtypes': {
      'keypress': {'event': Event.MOUSEMOVE, 'setter': function(f) { document.onMousemove = f; } },
      'mousemove': {'event': Event.KEYPRESS, 'setter': function(f) { document.onKeypress = f; } },
    },
  };
  var IE4EventModel = {
    'install': function(eventtype, f) {
      eventtype(f);
    },
    'uninstall': function(eventtype, f) {
      eventtype(null);
    },
    'eventtypes': {
      'keypress': function(f) { document.onMousemove = f; },
      'mousemove': function(f) { document.onKeypress = f; },
    },
  };

  function EventModel() {
    if (document.implementation.hasFeature("Events", "2.0")
        && document.addEventListener) {
      return DOM2EventModel;
    }
    if (document.attachEvent) {
      return IE5EventModel;
    }
    if (document.captureEvents) {
      return Netscape4EventModel;
    }
    return IE4EventModel;
    throw 'unknown EventModel';
  }

  var eventmodel = EventModel();

  // ----------------------------------------

  function RC4(key) {
    var S = new Array(256);

    function swap(i, j) {
      t = S[i];
      S[i] = S[j];
      S[j] = t;
    }
    
    var i;
    for (i=0;i<256;++i) {
      S[i] = i;
    }

    var j = 0;
    for (i=0;i<256;++i) {
      j = (j + S[i] + key[i % key.length]) % 256;
      swap(i, j);
    }

    i = 0;
    j = 0;
    this.getByte = function() {
      i = (i + 1) % 256;
      j = (j + S[i]) % 256;
      swap(i, j);
      return S[ (S[i] + S[j]) % 256 ];
    };
  }

  // ----------------------------------------

  function randomByte() { return Math.round(Math.random()*255)&255; }

  function timeByte() { return ((new Date().getTime())>>>2)&255; }
  this.timeByte = timeByte;

  // ----------------------------------------

  function TimerEntropy() {
    var pool = new Array(256);
    var next = 0;
    var read = 0;

    this.getByte = function() {
      return pool[(read++)&255];
    }

    var active = false;

    function eventhandler() {
      var t = timeByte(); // load time
      for(var i=0; i<256; i++) {
        t ^= randomByte();
        pool[(next++)&255] ^= t;
      }
      if (active) {
        window.setTimeout(eventhandler, randomByte()|128);
      }
    }

    this.start = function() {
      active = true;
      window.setTimeout(eventhandler, 0);
    }
    this.stop = function() {
      active = false;
    }
  }
  var timerEntropy = new TimerEntropy();

  // ----------------------------------------
  function KeyPressEntropy() {
    var pool = new Array(256);
    var read = 0;
    var next = 0;

    this.getByte = function() {
     return pool[(read++)&255];
    };

    function eventhandler(e) {
     pool[(next++)&255] ^= timeByte();
    }
    var keyevent = eventmodel.eventtypes.keypress;
    this.start = function() {
      eventmodel.install(keyevent, eventhandler);
    };
    this.stop = function() {
      eventmodel.uninstall(keyevent, eventhandler);
    }
  }
  var keypressEntropy = new KeyPressEntropy();

  // ----------------------------------------
  function MouseMoveEntropy() {
    var pool = new Array(256);
    var read = 0;
    var next = 0;

    this.getByte = function() {
      return pool[(read++)&255];
    };


    var mouseMoveSkip = 0; // Delay counter for mouse entropy collection
    var oldMoveHandler;    // For saving and restoring mouse move handler in IE4

    var key = new Array(256);
    var i;
    for (i=0; i<256; i++) {
      key[i] = randomByte()^timeByte();
    }
    var rc4 = new RC4(key);

    function eventhandler(e) {
      if (!e) { e = window.event; }	    // Internet Explorer event model

      if (mouseMoveSkip-- <= 0) {
        var c;
        if (oldMoveHandler) {
          c = ((e.clientX << 4) | (e.clientY & 15));
        } else {
          c = ((e.screenX << 4) | (e.screenY & 15));
        }

        pool[(next++)%256] ^= (rc4.getByte() ^ (c&255));
        pool[(next++)%256] ^= (rc4.getByte() ^ (timeByte()&255));
        mouseMoveSkip = randomByte() & 7;
      }
    }
    var mouseevent = eventmodel.eventtypes.mousemove;
    this.start = function() {
      eventmodel.uninstall(mouseevent, eventhandler);
    };
    this.stop = function() {
      eventmodel.install(mouseevent, eventhandler);
    };
  }
  var mousemoveEntropy = new MouseMoveEntropy();

  this.getByte = function() {
    return timerEntropy.getByte()^keypressEntropy.getByte()^mousemoveEntropy.getByte();
  };

  this.startCollect = function() {
    timerEntropy.start();
    keypressEntropy.start();
    mousemoveEntropy.start();
  };

  this.endCollect = function() {
    timerEntropy.stop();
    keypressEntropy.stop();
    mousemoveEntropy.stop();
  };
}
