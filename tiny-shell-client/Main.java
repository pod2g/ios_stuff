import java.io.OutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.net.Socket;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

public class Main {
	private String host;
	private int port;
	private Socket s = null;
	private OutputStream out;
	private InputStream in;

	private Main(String host, int port) {
		this.host = host;
		this.port = port;
	}

	public void connect() throws IOException {
		this.s = new Socket(this.host, this.port);
		this.out = new BufferedOutputStream(s.getOutputStream());
		this.in = s.getInputStream();
	}

	public void close() throws IOException {
		if (this.s != null) s.close();
	}

	public void execve(String path) throws IOException {
		writeString("execve");
		writeString(path);
		writeUInt32(1);
		writeString(new File(path).getName());
		this.out.flush();
	}

	public void upload(String lpath, String rpath, int mods) throws IOException {
		writeString("upload");
		writeString(rpath);
		writeUInt32(mods);
		File f = new File(lpath);
		if (!f.exists()) throw new FileNotFoundException("File does not exists: " + f.getAbsolutePath());
		writeUInt32((int) f.length()); // sorry, I know casting from long to int sucks...
		byte[] buf = new byte[1024];
		int c;
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(f);
			while ((c = fis.read(buf)) > 0) {
				this.out.write(buf, 0, c);
			}
		} finally {
			if (fis != null) fis.close();
		}
		this.out.flush();
	}

	private void writeUInt32(int i) throws IOException {
		byte[] b = new byte[4];
		b[0] = (byte) ((i) & 0xff);
		b[1] = (byte) ((i >> 8) & 0xff);
		b[2] = (byte) ((i >> 16) & 0xff);
		b[3] = (byte) ((i >> 24) & 0xff);
		this.out.write(b);
	}

	private void writeString(String s) throws IOException {
		writeUInt32(s.length());
		this.out.write(s.getBytes());
	}

	public static void usage() {
		System.out.println("syntax: -u <ip>:<port> <local path> <remote path> <file mods>");
		System.out.println("or syntax: -e <ip>:<port> <binary path>");
		System.exit(1);
	}

	public static void main(String[] args) throws Exception {
		if (args.length < 1) usage();
		String mode = args[0];

		if (mode.equals("-u")) {
			if (args.length != 5) usage();
		} else if (mode.equals("-e")) {
			if (args.length != 3) usage();
		} else {
			usage();
		}

		if (args[1].split(":").length != 2) usage();
		String host = args[1].split(":")[0];
		int port = Integer.parseInt(args[1].split(":")[1], 10);

		Main m = new Main(host, port);

		if (mode.equals("-u")) {
			String lpath = args[2];
			String rpath = args[3];
			int mods = Integer.parseInt(args[4], 8);
			try {
				m.connect();
				m.upload(lpath, rpath, mods);
			} finally {
				m.close();
			}
		} else if (mode.equals("-e")) {
			String path = args[2];
			try {
				m.connect();
				m.execve(path);
			} finally {
				m.close();
			}
		}
	}
}
