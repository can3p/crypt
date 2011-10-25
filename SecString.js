;(function() {

	if(!window.Crypt) {
		window.Crypt = {};
	}

	var sessionKey = [];

	Crypt.SecString = function(str)
	{
		if(sessionKey.length == 0) {
			Crypt.SecString.generateSessionKey();
		}

		this._crypt = "";
		this.save(str);
	}

	Crypt.SecString.generateSessionKey = function()
	{
		sessionKey = Crypt.RC4.generateSessionKey();
	}

	Crypt.SecString.prototype = {
		save: function(str)
		{
			this._crypt = Crypt.RC4.encrypt( sessionKey, str );
		},

		get: function()
		{
			return Crypt.RC4.decrypt( sessionKey, this._crypt );
		}
	};

})();
