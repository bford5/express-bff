export const localLogger = (message, dataToLog) => {
	console.log('--------------------------------');
	console.log(new Date().toISOString());
	console.log(message);
	if (dataToLog) {
		console.log(dataToLog);
	}
	console.log('--------------------------------');
};