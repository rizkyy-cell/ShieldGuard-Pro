const express = require('express');
const cors = require('cors');
const axios = require('axios');
const multer = require('multer');
const FormData = require('form-data');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Gunakan multer untuk menyimpan file sementara di memory sebelum dikirim ke VT
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 4 * 1024 * 1024 } }); // Limit 4MB untuk Vercel Free

// Middleware untuk mengecek API Key di Environment Vercel
const getApiKey = () => {
    const key = process.env.VT_API_KEY;
    if (!key) throw new Error("API Key belum disetting di Vercel!");
    return key;
};

// 1. ENDPOINT: Scan URL
app.post('/api/scan/url', async (req, res) => {
    try {
        const response = await axios.post('https://www.virustotal.com/api/v3/urls', 
            { url: req.body.url }, 
            { headers: { 'x-apikey': getApiKey(), 'Content-Type': 'application/x-www-form-urlencoded' }}
        );
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ error: error.response?.data || error.message });
    }
});

// 2. ENDPOINT: Cek Hash (Sangat Cepat)
app.get('/api/scan/hash/:hash', async (req, res) => {
    try {
        const response = await axios.get(`https://www.virustotal.com/api/v3/files/${req.params.hash}`, {
            headers: { 'x-apikey': getApiKey() }
        });
        res.json(response.data);
    } catch (error) {
        // Jika status 404, artinya file belum pernah di-scan oleh siapapun di dunia
        if(error.response && error.response.status === 404) {
            return res.status(404).json({ message: "Hash not found" });
        }
        res.status(500).json({ error: error.response?.data || error.message });
    }
});

// 3. ENDPOINT: Polling (Cek Status)
app.get('/api/scan/poll/:id', async (req, res) => {
    try {
        const response = await axios.get(`https://www.virustotal.com/api/v3/analyses/${req.params.id}`, {
            headers: { 'x-apikey': getApiKey() }
        });
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ error: error.response?.data || error.message });
    }
});

// 4. ENDPOINT: Upload File Asli (Jika Hash tidak ditemukan)
app.post('/api/scan/file', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: "Tidak ada file" });

        const formData = new FormData();
        formData.append('file', req.file.buffer, req.file.originalname);

        const response = await axios.post('https://www.virustotal.com/api/v3/files', formData, {
            headers: { 'x-apikey': getApiKey(), ...formData.getHeaders() }
        });
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ error: error.response?.data || error.message });
    }
});

module.exports = app; // Wajib untuk serverless Vercel
                                          
