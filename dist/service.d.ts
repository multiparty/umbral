export declare namespace CryptoService {
    function init(): void;
    function hash(input: string): string;
    /**
     * Function for taking user inputs and returning values to be encrypted
     * @param {string} perpId - inputted perpetrator name
     * @param {string} userName - inputted user name
     * @returns {IPlainTextData} promise resolving a IPlainTextData object
     */
    function encryptData(randId: string, hashedUserName: string, publicKeys: Array<Uint8Array>): string;
}
