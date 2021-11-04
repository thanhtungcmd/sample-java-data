FROM adoptopenjdk/openjdk11:ubi

# Permission
RUN mkdir /var/www/
RUN chmod -R 777 /var/www/
WORKDIR /var/www
COPY momo.jar /var/www/momo.jar
COPY conf/ /var/www/conf
                                
CMD ["java", "-jar", "/var/www/momo.jar"]
EXPOSE "8080"