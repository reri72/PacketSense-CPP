#ifndef SINGLETON_H
#define SINGLETON_H

template <typename T>
class Singleton
{
    protected:
        Singleton() {}
        virtual ~Singleton() {}

    public:
        static T& getInstance()
        {
            static T instance;
            return instance;
        }

    private:
        Singleton(const Singleton&) = delete;
        Singleton& operator=(const Singleton&) = delete;
};

#endif // SINGLETON_H