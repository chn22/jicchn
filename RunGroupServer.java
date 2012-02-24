/* Driver program for FileSharing Group Server */

public class RunGroupServer {
	
	public static void main(String[] args) {
		if (args.length> 0) {
			try {
				GroupServer server = new GroupServer(Integer.parseInt(args[0]));
				server.start();
			}
			catch (NumberFormatException e) {
				System.out.printf("Enter a valid port number or pass no arguments to use the default port (%d)\n", GroupServer.SERVER_PORT);
			}
		}
		else {
			GroupServer server = new GroupServer();
			server.start();
		}
	}
}
