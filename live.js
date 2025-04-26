const load_date = Date.now();
const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const address = `${protocol}//${window.location.hostname}:##PORT##${window.location.pathname}`;
let socket = null;
function connect() {
	if (socket instanceof WebSocket) {
		if (socket.readyState === WebSocket.CONNECTING) {
			socket.onclose = function (ev) {
				setTimeout(connect, 1000);
			};
			socket.close();
			return;
		}
	}
	if (socket === null || socket.readyState !== WebSocket.OPEN){
		socket = new WebSocket(address);
		socket.onmessage = function (ev) {
			if (ev.data == 'reload')
				window.location.reload();
		};
		socket.onopen = function (ev) {
			console.info('Live reload connected.');
			socket.send(load_date.toString());
		};
		socket.onclose = function (ev) {
			console.error('Live reload websocket closed with code', ev.code);
		};
	}
	setTimeout(connect, 1000);
}
connect();
