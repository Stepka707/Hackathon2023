document.getElementById("myForm").addEventListener("submit", function (event) {
    event.preventDefault(); // Prevent the default form submission behavior

    const name = document.getElementById("name").value;
    const email = document.getElementById("email").value;
    const message = document.getElementById("message").value;

    // Create a Blob (Binary Large Object) containing the form data
    const formData = new Blob([`Name: ${name}\nEmail: ${email}\nMessage: ${message}`], { type: 'text/plain' });

    // Create an object URL to reference the Blob
    const url = URL.createObjectURL(formData);

    // Create a download link
    const a = document.createElement('a');
    a.href = url;
    a.download = 'formData.txt'; // Specify the file name
    a.style.display = 'none';
    document.body.appendChild(a);

    // Simulate a click on the link to trigger the download
    a.click();

    // Clean up by revoking the object URL
    URL.revokeObjectURL(url);
});
