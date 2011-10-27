if(!window.console) {
	window.console = {};
}

console.echoBinStr = function(name, str)
{
	var res = [];
	for(var i=0, j=str.length; i < j; ++i)
	{
		var chr = str.charCodeAt(i).toString(16);

		chr = ((chr.length == 1)?'0':'') + chr;
		res.push(chr);
	}
	console.log(name + ' = "' + res.join(' ') + '"');
}

console.echoHex = function( name, num )
{
	console.log(name + ' = "' + num.toString(16) + '"');
}

console.echo = function( name, num )
{
	console.log(name + ' = "' + num.toString() + '"');
}

String.prototype.toByteArray = function()
{
	var res = [];
	for(var i=0, j=this.length; i < j; ++i)
	{
		var chr = this.charCodeAt(i);
		res.push(chr);
	}

	return res;
}

String.prototype.toHexString = function()
{
	var res = [];
	for(var i=0, j=this.length; i < j; ++i)
	{
		var chr = this.charCodeAt(i).toString(16);

		chr = ((chr.length == 1)?'0':'') + chr;
		res.push(chr);
	}
	return res.join(' ').toUpperCase();
}

String.prototype.toByteString = function()
{
	 var ar = this.split(' '),
		 res = "";

	 for(var i = 0; i < ar.length; ++i)
	 {
		res += String.fromCharCode( parseInt(ar[i], 16) );
	 }

	 return res;
}

String.prototype.toNumber = function()
{
	var res = 0;

	for(var i = this.length - 1; i >= 0; --i) {
		res += res * 256 + this.charCodeAt( i );
	}

	return res;
}

String.fromByteArray = function(arr)
{
	var res = "";
	for(var i=0, j=arr.length; i < j; ++i)
	{
		res += String.fromCharCode(arr[i]);
	}

	return res;
}

