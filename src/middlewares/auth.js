import jwt from 'jsonwebtoken';

const auth = async (req, res, next) => {
    try {
        const token = req.header('Authorization').split('Bearer ')[1];

        if (!token) {
            return res.status(404).json({
                success: false,
                message: 'Token not found!'
            });
        }
        
        const payload = jwt.verify(token, process.env.SECRET_KEY);
        const userId = payload.userId;
        req.userId = userId;

        next();
    } catch(e) {
        res.status(400).json({
            success: false,
            message: `Error while authentication of token! ${e.message}`
        });
    }
}

export default auth;
