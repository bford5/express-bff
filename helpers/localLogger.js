export const localLogger = (message, dataToLog) => {
	if (process.env.NODE_ENV === 'production') return;
	console.log('--------------------------------');
	console.log(new Date().toISOString());
	console.log(message);
	if (dataToLog) {
		console.log(dataToLog);
	}
	console.log('--------------------------------');
};