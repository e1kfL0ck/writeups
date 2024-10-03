mysql -u root -p -h 127.0.0.1 -P 3306

mysql -u cactiuser -p -h 127.0.0.1 -P 3306


var noncedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse('PHXt3zvehfOnSoElAd3gC0zPOhMoWpHKkzRhovHRav8=') + '59be9ef39e4bdec37d2d3682bb03d7b9abadb304c841b7a498c02bec1acad87a')).toString(CryptoJS.enc.Base64);
