#!/usr/bin/ruby

require 'openssl'

def unhexlify(msg)
	[msg].pack("H*")
end

def decrypt(data, key, iv)
	algo = (key.length == 32) ? "AES-256-CBC" : "AES-128-CBC"
	aes = OpenSSL::Cipher.new(algo)
	aes.decrypt
	aes.key = key
	aes.iv = iv
	aes.padding = 0
	return aes.update(data) + aes.final
end

def valid(data)
	return "kernel" if data.index("complzss") == 0
	return "ramdisk" if data[0x400..0x401] == "H+"
	return "bootload" if data[0x280..0x284] == "iBoot"
	return "devicetree" if data.index("serial-number")
	return "bootlogo" if data.index("iBootIm") == 0
end

if ARGV.length < 1
	puts "Usage: img3decrypt.rb file.img3 [KEY] [IV] [output]"
	exit(-1)
end

filename = ARGV.shift
key = unhexlify(ARGV.shift)
iv = unhexlify(ARGV.shift)
output = ARGV.shift

output = "#{filename}.dec" if not output

File.open(filename, "rb") { |io|

	magic,fullsize = io.read(20).unpack("A4V")

	raise "3gmI magic not found" if magic != "3gmI"

	while !io.eof?
		tag, len, len2 = io.read(12).unpack("A4VV")
		
		raise "Invalid tag length" if len < 12

		data = io.read(len-12)
		
		if tag == "ATAD"
			t = valid(data)
			if t
				puts "Image is not encrypted (#{t})"
			else
				data = decrypt(data, key, iv)
				t = valid(data)
				puts t ? "Image decrypted OK (#{t})" : "Bad key/IV ?"
			end
			puts "Writing DATA payload to #{output}"
			File.open(output, "wb") {|f| f.write(data) }
			break
		end
	end
}

