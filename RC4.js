(function(Crypt) {
		Crypt.RC4 = {
			generateSessionKey: function()
			{
				var arr = new Array(32),
					min = 0, max = 255;

				for( var i = 0; i < arr.length; ++i ) {
					arr[ i ] = Math.floor(Math.random() * (max - min + 1)) + min;
				}

				return arr;
			},

			encrypt: function( key, data )
			{
				if( key.length == 0 || data.length == 0 ) {
					console.log('RC4: empty key or data');
					return "";
				}

				var result = "";

				var S = [],
					i;

				for( i = 0; i < 256; ++i )
					S[ i ] = i;

				var btBufDep = (data.length & 0xFF) << 1,
					i = 0,
					j = 0,
					k = 0,
					t, w;

				//key setup
				for( w = 0; w < 256; ++w ) {
					j += S[ w ] + key[ k ] + btBufDep;

					t = S[ i ]; S[ i ] = S[ j ]; S[ j ] = t;
					++k;
					if( k == key.length )
						k = 0;
				}

				i = 0, j = 0;
				for( w = 0; w < data.length; ++w ) {
					++i;
					j += S[ i ];

					t = S[ i ]; S[ i ] = S[ j ]; S[ j ] = t;
					t = S[ i ] + S[ j ];

					result += String.fromCharCode( data.charCodeAt( w ) ^ S[ t ] );
				}

				return result;
			},

			decrypt: function( key, crypt )
			{
				return this.encrypt( key, crypt );
			}
		}
})(window.Crypt = window.Crypt || {});
