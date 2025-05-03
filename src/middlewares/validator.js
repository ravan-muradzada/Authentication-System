import validator from 'validator';

const validateRequest = (req, res, next) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({
                success: false,
                message: 'Email required for authentication!'
            });
        }
        if (!validator.isEmail(email)) {
            return res.status(400).json({
                success: false,
                message: 'Email format is wrong!'
            });
        }

        next();
    } catch(e) {
        res.status(400).json({
            success: false,
            message: 'Error happened while validating request!'
        });
    }
}

export default validateRequest;
