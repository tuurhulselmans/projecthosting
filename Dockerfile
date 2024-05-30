FROM python:3.11.0-alpine
WORKDIR /ProjectHostingTeam1
EXPOSE 8000
COPY ./requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --upgrade -r ./requirements.txt
COPY ./klein_duimpje /ProjectHostingTeam1
RUN mkdir -p /code/sqlitedb
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]