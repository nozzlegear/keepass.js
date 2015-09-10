export function fetchArrayBuffer(path) {
    return fetch(path).then(function (response) {
        return response.arrayBuffer(); 
    });
};